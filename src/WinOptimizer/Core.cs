using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Media;
using Microsoft.Win32;

namespace WinOptimizer
{
    public enum Difficulty { Easy = 0, Medium = 1, Hard = 2 }
    public enum Impact { Low = 0, Medium = 1, High = 2 }
    /// <summary>How badly things can go wrong if the change is made carelessly.</summary>
    public enum Risk { None = 0, Low = 1, Moderate = 2, High = 3, Critical = 4 }

    public class Recommendation
    {
        public string Category { get; set; }
        public string Title { get; set; }
        public string Finding { get; set; }
        public string Why { get; set; }
        public string Where { get; set; }
        public List<string> Steps { get; set; } = new List<string>();
        public Difficulty Difficulty { get; set; }
        public Impact Impact { get; set; }
        public Risk Risk { get; set; }
        public string RiskNote { get; set; }

        /// <summary>Optional list shown as bullets under the finding.</summary>
        public List<string> Items { get; set; } = new List<string>();
        public List<string> BulletItems => Items.Select(s => "•  " + s).ToList();

        /// <summary>Optional Windows page to open for the user: "target" or "target|arguments". Opening it changes nothing.</summary>
        public string Open { get; set; }
        public string OpenLabel { get; set; }

        public Recommendation Link(string target, string label)
        {
            Open = target; OpenLabel = label + "  ↗";
            return this;
        }

        public int Score =>(int)Impact * 3 - (int)Difficulty - (int)Risk * 2;

        public List<string> NumberedSteps => Steps.Select((s, i) => (i + 1) + ".  " + s).ToList();

        public string DifficultyText => "Difficulty: " + Difficulty;
        public string ImpactText => "Impact: " + Impact;
        public string RiskText => "Threat: " + RiskLabel(Risk);

        public static string RiskLabel(Risk r)
        {
            switch (r)
            {
                case Risk.None: return "No damage threat";
                case Risk.Low: return "Low";
                case Risk.Moderate: return "Moderate";
                case Risk.High: return "High";
                default: return "Could cripple Windows";
            }
        }

        public Brush DifficultyBg => Palette.Bg(Difficulty == Difficulty.Easy ? 0 : Difficulty == Difficulty.Medium ? 2 : 3);
        public Brush DifficultyFg => Palette.Fg(Difficulty == Difficulty.Easy ? 0 : Difficulty == Difficulty.Medium ? 2 : 3);
        public Brush RiskBg => Palette.Bg((int)Risk);
        public Brush RiskFg => Palette.Fg((int)Risk);
        public Brush ImpactBg => Palette.ImpactBg[(int)Impact];
        public Brush ImpactFg => Palette.ImpactFg[(int)Impact];
    }

    internal static class Palette
    {
        static Brush B(string hex)
        {
            var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
            b.Freeze();
            return b;
        }

        // 0 green, 1 lime, 2 amber, 3 red, 4 deep red
        static readonly Brush[] bg = { B("#DDEFE3"), B("#E9F0D3"), B("#F8ECCF"), B("#F6D8D5"), B("#E7B4B4") };
        static readonly Brush[] fg = { B("#2F6B45"), B("#56661F"), B("#7A5A12"), B("#8C2F2F"), B("#641818") };
        public static Brush Bg(int i) => bg[Math.Max(0, Math.Min(4, i))];
        public static Brush Fg(int i) => fg[Math.Max(0, Math.Min(4, i))];

        public static readonly Brush[] ImpactBg = { B("#ECEEF2"), B("#DCE7F5"), B("#C6D9F1") };
        public static readonly Brush[] ImpactFg = { B("#5A6373"), B("#2F527F"), B("#1E4070") };
    }

    public class SystemSummary
    {
        public string Os = "Windows";
        public int Build;
        public bool IsWin11;
        public string Cpu = "Unknown";
        public int Threads;
        public double RamGb;
        public int MemLoad;
        public string Gpu = "Unknown";
        public bool? SystemDriveIsSsd;
        public long DiskTotal, DiskFree;
        public bool HasBattery;
        public bool IsAdmin;
        public TimeSpan Uptime;
        public double? BootSeconds;
        public int StartupCount;
        public int ProcessCount;
        public string TopProcesses = "";
    }

    public class ScanResult
    {
        public SystemSummary Sys;
        public List<Recommendation> Recs;
        public DateTime When;
        public double Seconds;
    }

    internal class ScanContext
    {
        public SystemSummary Sys = new SystemSummary();
        public List<Recommendation> Recs = new List<Recommendation>();
        public HashSet<string> RunningNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public Recommendation Add(string cat, string title, string finding, string why, string where,
            Difficulty d, Impact i, Risk r, string riskNote, params string[] steps)
        {
            var rec = new Recommendation
            {
                Category = cat, Title = title, Finding = finding, Why = why, Where = where,
                Difficulty = d, Impact = i, Risk = r, RiskNote = riskNote, Steps = steps.ToList()
            };
            Recs.Add(rec);
            return rec;
        }
    }

    /// <summary>Read-only registry helpers. Nothing in this program writes to the registry.</summary>
    internal static class Reg
    {
        public static RegistryKey Open(RegistryHive hive, string path, RegistryView view = RegistryView.Registry64)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, view))
                    return b.OpenSubKey(path, false);
            }
            catch { return null; }
        }

        public static object Get(RegistryHive hive, string path, string name, RegistryView view = RegistryView.Registry64)
        {
            try
            {
                using (var k = Open(hive, path, view))
                    return k?.GetValue(name);
            }
            catch { return null; }
        }

        public static int? GetInt(RegistryHive hive, string path, string name)
        {
            return AsInt(Get(hive, path, name));
        }

        public static string GetStr(RegistryHive hive, string path, string name)
        {
            return Get(hive, path, name) as string;
        }

        public static int? AsInt(object o)
        {
            try
            {
                if (o is int i) return i;
                if (o is long l) return (int)l;
                if (o is string s && int.TryParse(s, out var p)) return p;
            }
            catch { }
            return null;
        }
    }

    internal static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        public class MEMORYSTATUSEX
        {
            public uint dwLength = 64;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile,
                         ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX buffer);

        [DllImport("kernel32.dll")]
        public static extern ulong GetTickCount64();

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_POWER_STATUS
        {
            public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag;
            public int BatteryLifeTime, BatteryFullLifeTime;
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

        [StructLayout(LayoutKind.Sequential)]
        public struct SHQUERYRBINFO
        {
            public int cbSize;
            public long i64Size;
            public long i64NumItems;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern int SHQueryRecycleBin(string root, ref SHQUERYRBINFO info);

        public static bool IsAdmin
        {
            get
            {
                try
                {
                    using (var id = WindowsIdentity.GetCurrent())
                        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch { return false; }
            }
        }
    }

    internal static class Util
    {
        public static string Bytes(long b)
        {
            if (b >= 1L << 30) return (b / (double)(1L << 30)).ToString("0.#") + " GB";
            if (b >= 1L << 20) return (b / (double)(1L << 20)).ToString("0") + " MB";
            return (b / 1024.0).ToString("0") + " KB";
        }

        /// <summary>Pulls the executable path out of a command line such as a Run value or service ImagePath.</summary>
        public static string ExtractExe(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return null;
            try
            {
                cmd = Environment.ExpandEnvironmentVariables(cmd.Trim());
                if (cmd.StartsWith(@"\??\")) cmd = cmd.Substring(4);
                if (cmd.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                    cmd = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + cmd.Substring(11);
                if (cmd.StartsWith("\""))
                {
                    int e = cmd.IndexOf('"', 1);
                    return e > 1 ? cmd.Substring(1, e - 1) : null;
                }
                int i = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                return i > 0 ? cmd.Substring(0, i + 4) : cmd;
            }
            catch { return null; }
        }

        public static bool ContainsAny(string haystack, params string[] needles)
        {
            if (string.IsNullOrEmpty(haystack)) return false;
            foreach (var n in needles)
                if (haystack.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        /// <summary>Names that belong to security products. These are never suggested for disabling or removal.</summary>
        public static readonly string[] SecurityWords =
        {
            "defender", "securityhealth", "antivirus", "anti-virus", "antimalware", "anti-malware", "malwarebytes",
            "norton", "mcafee", "bitdefender", "kaspersky", "eset", "avast", "avg ", "avira", "sophos",
            "trend micro", "webroot", "f-secure", "crowdstrike", "sentinelone", "firewall", "vpn", "bitlocker",
            "password", "authenticator", "yubi", "endpoint"
        };
    }
}
