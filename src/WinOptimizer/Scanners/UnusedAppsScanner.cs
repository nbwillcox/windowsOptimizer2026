using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace WinOptimizer.Scanners
{
    /// <summary>
    /// Best-effort detection of installed programs that have not been used for over a year.
    /// Windows keeps no reliable "last used" date, so several weak signals are combined and every
    /// result is labelled with a confidence level. Read-only.
    /// </summary>
    internal static class UnusedAppsScanner
    {
        static readonly string[] SkipNames =
        {
            "redistributable", "runtime", " sdk", "driver", "webview", "update", "microsoft edge", "hotfix",
            "service pack", "language pack", "targeting pack", "chipset", "firmware", "bios", "windows ",
            ".net", "visual c++", "directx", "codec"
        };
        static readonly string[] SkipPublishers =
        {
            "intel", "nvidia", "advanced micro devices", "amd", "realtek", "qualcomm", "synaptics", "mediatek", "broadcom"
        };

        class Hit { public Recommendation Rec; public int Conf; public long Size; }

        public static void Scan(ScanContext ctx)
        {
            var lnks = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            var launched = ReadUserAssist(lnks);
            bool prefetchOk = ReadPrefetch(launched);

            DateTime cutoff = DateTime.Now.AddDays(-365);
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var blockedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Trim(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)),
                Trim(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)),
                Trim(Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles)),
                Trim(Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86)),
                Trim(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
                Trim(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
                Trim(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
            };

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var hits = new List<Hit>();
            const string path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            var sources = new[]
            {
                Tuple.Create(RegistryHive.LocalMachine, RegistryView.Registry64),
                Tuple.Create(RegistryHive.LocalMachine, RegistryView.Registry32),
                Tuple.Create(RegistryHive.CurrentUser, RegistryView.Registry64),
            };

            foreach (var src in sources)
            {
                using (var root = Reg.Open(src.Item1, path, src.Item2))
                {
                    if (root == null) continue;
                    foreach (var sub in root.GetSubKeyNames())
                    {
                        try
                        {
                            using (var k = root.OpenSubKey(sub))
                            {
                                var hit = Evaluate(k, ctx, launched, lnks, prefetchOk, cutoff, winDir, blockedDirs, seen);
                                if (hit != null) hits.Add(hit);
                            }
                        }
                        catch { }
                    }
                }
            }

            foreach (var h in hits.OrderByDescending(h => h.Conf).ThenByDescending(h => h.Size).Take(30))
                ctx.Recs.Add(h.Rec);
        }

        static string Trim(string p) => (p ?? "").TrimEnd('\\');

        static Hit Evaluate(RegistryKey k, ScanContext ctx, Dictionary<string, DateTime> launched,
            Dictionary<string, DateTime> lnks, bool prefetchOk, DateTime cutoff, string winDir,
            HashSet<string> blockedDirs, HashSet<string> seen)
        {
            if (k == null) return null;
            string name = (k.GetValue("DisplayName") as string ?? "").Trim();
            if (name.Length == 0) return null;
            if (Reg.AsInt(k.GetValue("SystemComponent")) == 1) return null;
            if (k.GetValue("ParentKeyName") != null) return null;
            if (string.IsNullOrEmpty(k.GetValue("UninstallString") as string)) return null;
            string publisher = k.GetValue("Publisher") as string ?? "";
            if (Util.ContainsAny(name, SkipNames) || Util.ContainsAny(publisher, SkipPublishers)) return null;
            if (Util.ContainsAny(name + " " + publisher, Util.SecurityWords)) return null; // never suggest removing security software
            if (!seen.Add(name)) return null;

            // Recently installed or updated programs are left alone.
            string inst = k.GetValue("InstallDate") as string;
            if (inst != null && DateTime.TryParseExact(inst, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var instDate) && instDate > cutoff)
                return null;

            string dir = Trim((k.GetValue("InstallLocation") as string ?? "").Trim().Trim('"'));
            if (dir.Length == 0)
            {
                string icon = (k.GetValue("DisplayIcon") as string ?? "").Trim();
                int comma = icon.LastIndexOf(',');
                if (comma > 2) icon = icon.Substring(0, comma);
                icon = icon.Trim('"');
                try { if (icon.Length > 3) dir = Trim(Path.GetDirectoryName(icon) ?? ""); } catch { }
            }
            if (dir.Length <= 3 || blockedDirs.Contains(dir)) return null;
            if (dir.StartsWith(winDir, StringComparison.OrdinalIgnoreCase)) return null;
            if (!Directory.Exists(dir)) return null;
            if (Directory.GetCreationTime(dir) > cutoff) return null;

            var exes = FindExes(dir);
            if (exes.Count == 0) return null;

            DateTime? lastRun = null;
            DateTime lastAccess = DateTime.MinValue;
            foreach (var exe in exes)
            {
                string file = Path.GetFileName(exe);
                if (ctx.RunningNames.Contains(Path.GetFileNameWithoutExtension(file))) return null; // in use right now
                if (launched.TryGetValue(file, out var t) && (lastRun == null || t > lastRun)) lastRun = t;
                // Prefetch truncates long names to 29 characters.
                if (file.Length > 29 && launched.TryGetValue(file.Substring(0, 29), out t) && (lastRun == null || t > lastRun)) lastRun = t;
                try
                {
                    var a = File.GetLastAccessTime(exe);
                    if (a > lastAccess) lastAccess = a;
                }
                catch { }
            }
            foreach (var l in lnks)
                if (l.Key.Length >= 4 && name.IndexOf(l.Key, StringComparison.OrdinalIgnoreCase) >= 0 && (lastRun == null || l.Value > lastRun))
                    lastRun = l.Value;

            int conf; string evidence;
            if (lastRun.HasValue)
            {
                if (lastRun.Value > cutoff) return null;
                bool accessOld = lastAccess < cutoff;
                conf = accessOld ? 3 : 2;
                evidence = "Last recorded launch: " + lastRun.Value.ToString("d MMM yyyy") + "." +
                           (accessOld ? "" : " Its files were read more recently, which may just be an antivirus scan or an updater.");
            }
            else
            {
                if (lastAccess > cutoff) return null;
                conf = prefetchOk ? 2 : 1;
                evidence = "Windows has no record of it being launched, and its program files were last accessed " +
                           lastAccess.ToString("d MMM yyyy") + ".";
            }

            long size = (long)(Reg.AsInt(k.GetValue("EstimatedSize")) ?? 0) * 1024;
            string confText = conf == 3 ? "High" : conf == 2 ? "Medium" : "Low";
            bool w11 = ctx.Sys.IsWin11;

            return new Hit
            {
                Conf = conf, Size = size,
                Rec = new Recommendation
                {
                    Category = "Unused programs",
                    Title = "Possibly unused: " + name,
                    Finding = evidence + (size > 0 ? " Size: about " + Util.Bytes(size) + "." : "") +
                              " Confidence that it is unused: " + confText + "." +
                              (publisher.Length > 0 ? " Publisher: " + publisher + "." : ""),
                    Why = "Programs you no longer use take disk space and often leave updaters, services and startup entries running. " +
                          "Windows does not track usage reliably, so treat this as a prompt to check, not a verdict: programs started by " +
                          "other programs, from a command line, or by another user account may not leave a launch record.",
                    Where = w11 ? "Settings > Apps > Installed apps" : "Settings > Apps > Apps & features",
                    Open = "ms-settings:appsfeatures",
                    OpenLabel = "Open installed apps  ↗",
                    Difficulty = Difficulty.Easy,
                    Impact = size > 5L << 30 ? Impact.Medium : Impact.Low,
                    Risk = Risk.Low,
                    RiskNote = "No risk to Windows itself. You lose the program and possibly its settings or saved data. " +
                               "Make sure you really do not need it and still have any licence key or installer before removing it.",
                    Steps = new List<string>
                    {
                        "Ask yourself whether you recognise \"" + name + "\" and still need it. If unsure, search its name online first.",
                        "Open Settings (Win+I) > Apps > " + (w11 ? "Installed apps." : "Apps & features."),
                        "Find \"" + name + "\", click " + (w11 ? "the three dots, then Uninstall." : "it, then Uninstall."),
                        "Follow the uninstaller. To undo you would need to reinstall the program."
                    }
                }
            };
        }

        static List<string> FindExes(string dir)
        {
            var list = new List<string>();
            try
            {
                Add(list, dir);
                int n = 0;
                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    if (++n > 40 || list.Count > 150) break;
                    Add(list, sub);
                }
            }
            catch { }
            return list;
        }

        static void Add(List<string> list, string dir)
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir, "*.exe"))
                {
                    if (Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase)) continue;
                    list.Add(f);
                    if (list.Count > 150) return;
                }
            }
            catch { }
        }

        static string Rot13(string s)
        {
            var c = s.ToCharArray();
            for (int i = 0; i < c.Length; i++)
            {
                char ch = c[i];
                if (ch >= 'a' && ch <= 'z') c[i] = (char)((ch - 'a' + 13) % 26 + 'a');
                else if (ch >= 'A' && ch <= 'Z') c[i] = (char)((ch - 'A' + 13) % 26 + 'A');
            }
            return new string(c);
        }

        /// <summary>Explorer's own record of programs and shortcuts the current user has launched.</summary>
        static Dictionary<string, DateTime> ReadUserAssist(Dictionary<string, DateTime> lnks)
        {
            var exes = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var root = Reg.Open(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"))
                {
                    if (root == null) return exes;
                    foreach (var guid in root.GetSubKeyNames())
                    {
                        using (var count = root.OpenSubKey(guid + @"\Count"))
                        {
                            if (count == null) continue;
                            foreach (var vn in count.GetValueNames())
                            {
                                var data = count.GetValue(vn) as byte[];
                                if (data == null || data.Length < 68) continue;
                                long ft = BitConverter.ToInt64(data, 60);
                                if (ft <= 0) continue;
                                DateTime t;
                                try { t = DateTime.FromFileTime(ft); } catch { continue; }
                                string p = Rot13(vn);
                                string file = p.Substring(p.LastIndexOf('\\') + 1);
                                if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) Max(exes, file, t);
                                else if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) Max(lnks, file.Substring(0, file.Length - 4), t);
                            }
                        }
                    }
                }
            }
            catch { }
            return exes;
        }

        /// <summary>Prefetch files record the last run of each executable. Normally readable only as administrator.</summary>
        static bool ReadPrefetch(Dictionary<string, DateTime> exes)
        {
            try
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                bool any = false;
                foreach (var f in new DirectoryInfo(dir).EnumerateFiles("*.pf"))
                {
                    string n = f.Name;
                    int dash = n.LastIndexOf('-');
                    if (dash <= 0) continue;
                    Max(exes, n.Substring(0, dash), f.LastWriteTime);
                    any = true;
                }
                return any;
            }
            catch { return false; }
        }

        static void Max(Dictionary<string, DateTime> d, string key, DateTime t)
        {
            if (!d.TryGetValue(key, out var cur) || t > cur) d[key] = t;
        }
    }
}
