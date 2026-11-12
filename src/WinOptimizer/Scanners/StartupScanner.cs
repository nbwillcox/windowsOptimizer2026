using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace WinOptimizer.Scanners
{
    /// <summary>Lists programs that start with Windows (Run keys and Startup folders). Read-only.</summary>
    internal static class StartupScanner
    {
        class Entry { public string Name, Command, Source; }

        enum Verdict { Disable, Optional, Keep }

        class Known
        {
            public string[] Keys; public string Friendly; public Verdict V; public Impact I; public string Note;
            public Known(Verdict v, Impact i, string friendly, string note, params string[] keys)
            { V = v; I = i; Friendly = friendly; Note = note; Keys = keys; }
        }

        const string Manual = "The app still works normally when you open it yourself.";
        const string Sync = "Files stop syncing in the background until you open the app yourself.";
        const string Periph = "Custom lighting, macros or button profiles may not load until you open the app.";

        // Order matters: Keep entries are checked first so security and driver items are never flagged.
        static readonly Known[] Kb =
        {
            new Known(Verdict.Keep, Impact.Low, "Audio / input / graphics driver component", "",
                "rtkaud", "realtek", "synaptics", "syntp", "elantech", "igfx", @"\intel\", "nvidia", "nvbackend",
                "radeon", "amdrs", "ctfmon", "bluetooth", "thunderbolt", "waves", "dolby", "nahimic", "dts"),

            new Known(Verdict.Disable, Impact.High, "Microsoft Teams", Manual, "teams"),
            new Known(Verdict.Disable, Impact.High, "Docker Desktop", Manual, "docker"),
            new Known(Verdict.Disable, Impact.Medium, "Spotify", Manual, "spotify"),
            new Known(Verdict.Disable, Impact.Medium, "Discord", Manual, "discord"),
            new Known(Verdict.Disable, Impact.Medium, "Steam", Manual, "steam"),
            new Known(Verdict.Disable, Impact.Medium, "Epic Games Launcher", Manual, "epicgames"),
            new Known(Verdict.Disable, Impact.Medium, "Game launcher", Manual,
                "battle.net", "origin.exe", "eadesktop", "ealauncher", "ubisoft", "upc.exe", "galaxyclient", "riotclient", "rockstar"),
            new Known(Verdict.Disable, Impact.Medium, "Skype", Manual, "skype"),
            new Known(Verdict.Disable, Impact.Medium, "Slack", Manual, "slack"),
            new Known(Verdict.Disable, Impact.Low, "Zoom", Manual, "zoom"),
            new Known(Verdict.Disable, Impact.Low, "Messaging app", Manual, "whatsapp", "telegram", "signal.exe", "viber", "messenger"),
            new Known(Verdict.Disable, Impact.Medium, "Adobe background helper", Manual + " Adobe apps check for updates when opened instead.",
                "adobe", "creative cloud", "acrotray", "ccxprocess"),
            new Known(Verdict.Disable, Impact.Medium, "Microsoft Edge auto-launch", "Edge opens a little slower the first time.", "microsoftedgeautolaunch"),
            new Known(Verdict.Disable, Impact.Low, "Browser background launcher", Manual,
                "googlechromeautolaunch", "opera browser assistant", "opera stable", "brave", "vivaldi"),
            new Known(Verdict.Disable, Impact.Low, "Apple / iTunes helper", Manual, "itunes", "apple push", "applemobiledevice"),
            new Known(Verdict.Disable, Impact.Low, "Java update scheduler", "Java no longer checks for updates by itself; update it manually or uninstall it if unused.", "jusched", "sunjavaupdate"),
            new Known(Verdict.Disable, Impact.Low, "CCleaner monitor", Manual, "ccleaner"),
            new Known(Verdict.Disable, Impact.Medium, "Torrent client", Manual, "utorrent", "bittorrent", "qbittorrent"),
            new Known(Verdict.Disable, Impact.Medium, "Wallpaper Engine", "Animated wallpaper does not load until you start it.", "wallpaper32", "wallpaper64", "wallpaper engine"),
            new Known(Verdict.Disable, Impact.Low, "Cortana", Manual, "cortana"),
            new Known(Verdict.Disable, Impact.Low, "Productivity app", Manual, "grammarly", "evernote", "notion", "figma", "onenote"),
            new Known(Verdict.Disable, Impact.Medium, "PC maker support tool", "Driver and warranty notices from the PC maker stop until you open the tool.",
                "hpmsgsvc", "hp support", "hpsupport", "supportassist", "lenovo vantage", "myasus", "acer care"),

            new Known(Verdict.Optional, Impact.Medium, "Cloud sync client", Sync, "onedrive", "dropbox", "googledrivefs", "google drive", "icloud"),
            new Known(Verdict.Optional, Impact.Medium, "Peripheral software", Periph, "lghub", "logitech", "razer", "icue", "corsair", "steelseries", "armoury", "hyperx"),
        };

        public static void Scan(ScanContext ctx)
        {
            var entries = new List<Entry>();
            const string run = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            ReadRun(entries, RegistryHive.CurrentUser, RegistryView.Registry64, run, "Run", "Registry (current user)");
            ReadRun(entries, RegistryHive.LocalMachine, RegistryView.Registry64, run, "Run", "Registry (all users)");
            ReadRun(entries, RegistryHive.LocalMachine, RegistryView.Registry32, run, "Run32", "Registry (all users, 32-bit)");
            ReadFolder(entries, Environment.GetFolderPath(Environment.SpecialFolder.Startup), RegistryHive.CurrentUser, "Startup folder (current user)");
            ReadFolder(entries, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), RegistryHive.LocalMachine, "Startup folder (all users)");

            ctx.Sys.StartupCount = entries.Count;
            string where = ctx.Sys.IsWin11
                ? "Settings > Apps > Startup, or Task Manager > Startup apps"
                : "Task Manager > Startup tab, or Settings > Apps > Startup";

            foreach (var e in entries)
            {
                string text = (e.Name + " " + e.Command).ToLowerInvariant();
                if (Util.ContainsAny(text, Util.SecurityWords)) continue; // never touch security software

                Known k = null;
                foreach (var cand in Kb)
                    if (Util.ContainsAny(text, cand.Keys)) { k = cand; break; }

                if (k != null && k.V == Verdict.Keep) continue;

                string[] steps =
                {
                    "Click the 'Open Startup apps' button on this card (or open Settings > Apps > Startup).",
                    "Find \"" + e.Name + "\" in the list (the name shown there may be the program's full name) and switch it Off.",
                    "If it is not listed there: press Ctrl+Shift+Esc, open the " + (ctx.Sys.IsWin11 ? "'Startup apps'" : "'Startup'") + " tab, select it and click Disable.",
                    "To undo: switch it back On (or click Enable)."
                };
                string finding = "\"" + e.Name + "\" starts with Windows. Source: " + e.Source + ". Command: " + Short(e.Command);

                if (k == null)
                {
                    ctx.Add("Startup", "Review startup item: " + e.Name, finding,
                        "This program is not in WinOptimizer's list of known items. Every startup program lengthens boot and uses memory in the background, so disable it if you do not need it running all the time.",
                        where, Difficulty.Medium, Impact.Low, Risk.Low,
                        "Unknown item. Search its name online first. Disabling a startup entry never deletes the program and can be undone, but a driver or hardware utility may lose features until re-enabled.",
                        steps).Link("ms-settings:startupapps", "Open Startup apps");
                }
                else
                {
                    ctx.Add("Startup", "Stop " + k.Friendly + " from starting with Windows", finding,
                        "It loads at every sign-in and keeps running in the background, slowing boot and using memory even when you are not using it.",
                        where, Difficulty.Easy, k.I, k.V == Verdict.Optional ? Risk.Low : Risk.None,
                        k.Note + " Nothing is uninstalled and the change is fully reversible.",
                        steps).Link("ms-settings:startupapps", "Open Startup apps");
                }
            }
        }

        static string Short(string s)
        {
            if (string.IsNullOrEmpty(s)) return "(none)";
            return s.Length > 160 ? s.Substring(0, 157) + "..." : s;
        }

        /// <summary>Task Manager stores its enable/disable switch here. An odd first byte means disabled.</summary>
        static bool IsEnabled(RegistryHive hive, string approvedKey, string name)
        {
            var v = Reg.Get(hive, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\" + approvedKey, name) as byte[];
            return v == null || v.Length == 0 || (v[0] & 1) == 0;
        }

        static void ReadRun(List<Entry> list, RegistryHive hive, RegistryView view, string path, string approved, string source)
        {
            using (var k = Reg.Open(hive, path, view))
            {
                if (k == null) return;
                foreach (var name in k.GetValueNames())
                {
                    if (string.IsNullOrEmpty(name)) continue;
                    string cmd = Convert.ToString(k.GetValue(name));
                    if (string.IsNullOrWhiteSpace(cmd)) continue;
                    if (!IsEnabled(hive, approved, name)) continue;
                    list.Add(new Entry { Name = name, Command = cmd, Source = source });
                }
            }
        }

        static void ReadFolder(List<Entry> list, string folder, RegistryHive hive, string source)
        {
            try
            {
                if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
                foreach (var f in Directory.GetFiles(folder))
                {
                    string file = Path.GetFileName(f);
                    if (file.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!IsEnabled(hive, "StartupFolder", file)) continue;
                    list.Add(new Entry { Name = Path.GetFileNameWithoutExtension(f), Command = f, Source = source });
                }
            }
            catch { }
        }
    }
}
