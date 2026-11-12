using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace WinOptimizer.Scanners
{
    /// <summary>Hardware, Windows version, running processes and basic security posture. Read-only.</summary>
    internal static class SystemScanner
    {
        const RegistryHive HKLM = RegistryHive.LocalMachine;

        public static List<ManagementBaseObject> Wmi(string scope, string wql)
        {
            try
            {
                using (var s = new ManagementObjectSearcher(scope, wql))
                using (var r = s.Get())
                    return r.Cast<ManagementBaseObject>().ToList();
            }
            catch { return new List<ManagementBaseObject>(); }
        }

        public static void Scan(ScanContext ctx)
        {
            var sys = ctx.Sys;
            sys.IsAdmin = Native.IsAdmin;

            // --- Windows version
            const string cv = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            int.TryParse(Reg.GetStr(HKLM, cv, "CurrentBuild"), out sys.Build);
            sys.IsWin11 = sys.Build >= 22000;
            string product = Reg.GetStr(HKLM, cv, "ProductName") ?? "Windows";
            if (sys.IsWin11) product = product.Replace("Windows 10", "Windows 11");
            string ver = Reg.GetStr(HKLM, cv, "DisplayVersion");
            sys.Os = product + (ver != null ? " " + ver : "") + " (build " + sys.Build + ")";

            // --- CPU / RAM
            sys.Cpu = (Reg.GetStr(HKLM, @"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString") ?? "Unknown").Trim();
            sys.Threads = Environment.ProcessorCount;
            var mem = new Native.MEMORYSTATUSEX();
            if (Native.GlobalMemoryStatusEx(mem))
            {
                sys.RamGb = mem.ullTotalPhys / (double)(1L << 30);
                sys.MemLoad = (int)mem.dwMemoryLoad;
            }
            sys.Uptime = TimeSpan.FromMilliseconds(Native.GetTickCount64());
            if (Native.GetSystemPowerStatus(out var ps)) sys.HasBattery = (ps.BatteryFlag & 128) == 0 && ps.BatteryFlag != 255;

            // --- GPU
            var gpus = Wmi(@"root\cimv2", "SELECT Name FROM Win32_VideoController")
                .Select(g => g["Name"] as string).Where(n => !string.IsNullOrEmpty(n)).Distinct().ToList();
            if (gpus.Count > 0) sys.Gpu = string.Join(" + ", gpus);

            // --- System drive
            string root = Path.GetPathRoot(Environment.SystemDirectory);
            try
            {
                var di = new DriveInfo(root);
                sys.DiskTotal = di.TotalSize;
                sys.DiskFree = di.AvailableFreeSpace;
            }
            catch { }
            sys.SystemDriveIsSsd = DetectSsd(root[0]);

            sys.BootSeconds = LastBootSeconds();

            ScanProcesses(ctx);
            Hardware(ctx);
            Security(ctx);
        }

        static bool? DetectSsd(char letter)
        {
            const string scope = @"root\Microsoft\Windows\Storage";
            var disks = Wmi(scope, "SELECT DeviceId, MediaType FROM MSFT_PhysicalDisk");
            if (disks.Count == 0) return null;
            string diskNo = null;
            foreach (var p in Wmi(scope, "SELECT DiskNumber, DriveLetter FROM MSFT_Partition"))
            {
                try
                {
                    if (char.ToUpperInvariant(Convert.ToChar(p["DriveLetter"])) == char.ToUpperInvariant(letter))
                    {
                        diskNo = Convert.ToString(p["DiskNumber"]);
                        break;
                    }
                }
                catch { }
            }
            var match = disks.FirstOrDefault(d => Convert.ToString(d["DeviceId"]) == diskNo)
                        ?? (disks.Count == 1 ? disks[0] : null);
            if (match == null) return null;
            int media = Convert.ToInt32(match["MediaType"] ?? 0);
            if (media == 4) return true;
            if (media == 3) return false;
            return null;
        }

        /// <summary>Windows records each boot duration in a diagnostics log. Usually readable only as administrator.</summary>
        static double? LastBootSeconds()
        {
            try
            {
                var q = new EventLogQuery("Microsoft-Windows-Diagnostics-Performance/Operational",
                    PathType.LogName, "*[System[EventID=100]]") { ReverseDirection = true };
                using (var reader = new EventLogReader(q))
                using (var ev = reader.ReadEvent())
                {
                    if (ev == null) return null;
                    var m = Regex.Match(ev.ToXml(), "Name=['\"]BootTime['\"]>(\\d+)<");
                    if (m.Success) return long.Parse(m.Groups[1].Value) / 1000.0;
                }
            }
            catch { }
            return null;
        }

        static void ScanProcesses(ScanContext ctx)
        {
            var byName = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            int count = 0;
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    count++;
                    string n = p.ProcessName;
                    ctx.RunningNames.Add(n);
                    byName.TryGetValue(n, out long cur);
                    byName[n] = cur + p.WorkingSet64;
                }
                catch { }
                finally { p.Dispose(); }
            }
            ctx.Sys.ProcessCount = count;
            var top = byName.OrderByDescending(k => k.Value).Take(5).ToList();
            ctx.Sys.TopProcesses = string.Join(", ", top.Take(3).Select(t => t.Key + " " + Util.Bytes(t.Value)));

            if (ctx.Sys.MemLoad >= 75)
            {
                ctx.Add("Memory", "Memory is nearly full right now",
                    ctx.Sys.MemLoad + "% of RAM is in use. Biggest users: " +
                    string.Join(", ", top.Select(t => t.Key + " (" + Util.Bytes(t.Value) + ")")) + ".",
                    "When RAM fills up, Windows pushes data to the much slower disk (paging), which makes everything stutter.",
                    "Task Manager > Processes, sorted by Memory",
                    Difficulty.Easy, ctx.Sys.MemLoad >= 88 ? Impact.High : Impact.Medium, Risk.None,
                    "Closing an app only loses unsaved work in that app. Do not end processes you do not recognise.",
                    "Press Ctrl+Shift+Esc to open Task Manager.",
                    "Click the Memory column header to sort by memory use.",
                    "Close apps and browser tabs you are not using (close them normally rather than using End task).",
                    "If memory is always this full, see the startup recommendations and consider adding RAM.").Link("taskmgr.exe", "Open Task Manager");
            }
        }

        static void Hardware(ScanContext ctx)
        {
            var sys = ctx.Sys;
            if (sys.RamGb > 0 && sys.RamGb < 7.5)
            {
                ctx.Add("Hardware", "Add more memory (RAM)",
                    "This PC has " + sys.RamGb.ToString("0.#") + " GB of RAM.",
                    "Windows 10/11 plus a modern browser comfortably fill 8 GB. With less, the PC constantly swaps to disk. 16 GB is a good target.",
                    "Inside the PC (memory slots)",
                    Difficulty.Hard, Impact.High, Risk.None,
                    "No software risk. Requires buying compatible memory and opening the PC; some laptops have soldered RAM that cannot be upgraded.",
                    "Open Task Manager > Performance > Memory and note 'Slots used' and 'Speed'.",
                    "Look up your PC or motherboard model to find the supported memory type and maximum.",
                    "Buy matching modules and install them with the PC powered off and unplugged, or ask a repair shop.");
            }

            if (sys.SystemDriveIsSsd == false)
            {
                ctx.Add("Hardware", "Move Windows from the hard disk to an SSD",
                    "Windows is installed on a mechanical hard disk (HDD).",
                    "This is the single biggest speed-up available for an HDD-based PC: boot, app launches and updates are typically 3-10x faster on an SSD.",
                    "Inside the PC (storage drive)",
                    Difficulty.Hard, Impact.High, Risk.Low,
                    "Windows is not harmed, but a failed clone or reinstall can lose data. Back up first.",
                    "Back up your files to an external drive or cloud storage.",
                    "Buy an SSD at least as large as the space currently used on the system drive.",
                    "Clone the old drive to the SSD with the SSD maker's migration tool, or do a clean Windows install on the SSD.",
                    "Set the SSD as the first boot device in BIOS/UEFI.");
            }

            if (sys.Uptime.TotalDays >= 10)
            {
                ctx.Add("Boot", "Restart the PC",
                    "Windows has been running for " + (int)sys.Uptime.TotalDays + " days without a full restart.",
                    "Long sessions accumulate leaked memory and half-installed updates. With Fast Startup on, 'Shut down' does not fully reset Windows; 'Restart' does.",
                    "Start > Power > Restart",
                    Difficulty.Easy, Impact.Low, Risk.None, "None. Save your work first.",
                    "Save open work.", "Click Start > Power > Restart (not Shut down).");
            }

            if (sys.BootSeconds.HasValue && sys.BootSeconds.Value > 60)
            {
                ctx.Add("Boot", "Boot is slow",
                    "Windows recorded the last boot as taking " + sys.BootSeconds.Value.ToString("0") + " seconds.",
                    "Anything over about a minute usually points to too many startup programs, a hard disk system drive, or Fast Startup being off.",
                    "See the Startup, Boot and Hardware recommendations",
                    Difficulty.Easy, Impact.High, Risk.None, "None for reviewing. Follow the threat rating of each individual change.",
                    "Work through the Startup recommendations in this list first.",
                    "Check the Boot and Hardware recommendations (Fast Startup, SSD).",
                    "Restart and compare.");
            }
        }

        static void Security(ScanContext ctx)
        {
            // Antivirus state as reported by Windows Security Center.
            var av = SystemScanner.Wmi(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
            if (av.Count > 0)
            {
                bool anyOn = av.Any(a =>
                {
                    try { return ((Convert.ToInt32(a["productState"]) >> 12) & 0xF) == 1; } catch { return true; }
                });
                if (!anyOn)
                {
                    ctx.Add("Security", "Turn real-time antivirus protection back on",
                        "Windows reports no antivirus with real-time protection enabled (" +
                        string.Join(", ", av.Select(a => a["displayName"] as string)) + ").",
                        "Performance tuning should never trade away protection. Malware is also one of the most common causes of a slow PC.",
                        "Windows Security > Virus & threat protection",
                        Difficulty.Easy, Impact.High, Risk.None, "None. This makes the PC safer.",
                        "Open Start, type 'Windows Security' and open it.",
                        "Go to Virus & threat protection > Manage settings.",
                        "Turn Real-time protection On (or re-enable your third-party antivirus).").Link("windowsdefender://threat", "Open Windows Security");
                }
            }

            const string fw = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
            bool fwOff = Reg.GetInt(HKLM, fw + "StandardProfile", "EnableFirewall") == 0 ||
                         Reg.GetInt(HKLM, fw + "PublicProfile", "EnableFirewall") == 0;
            if (fwOff && SystemScanner.Wmi(@"root\SecurityCenter2", "SELECT displayName FROM FirewallProduct").Count == 0)
            {
                ctx.Add("Security", "Turn Windows Firewall back on",
                    "Windows Firewall is off for the private or public network profile and no other firewall is registered.",
                    "The firewall has no measurable performance cost and blocks unsolicited inbound connections.",
                    "Windows Security > Firewall & network protection",
                    Difficulty.Easy, Impact.High, Risk.None, "None. This makes the PC safer.",
                    "Open Start, type 'Windows Security' and open it.",
                    "Go to Firewall & network protection.",
                    "Open each network profile that shows Off and turn Microsoft Defender Firewall On.").Link("windowsdefender://network", "Open firewall settings");
            }

            if (Reg.GetInt(HKLM, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") == 0)
            {
                ctx.Add("Security", "Turn User Account Control (UAC) back on",
                    "UAC is disabled, so every program runs with full administrator rights without asking.",
                    "UAC costs nothing in performance and stops programs from silently changing system settings.",
                    "Control Panel > User Accounts > Change User Account Control settings",
                    Difficulty.Easy, Impact.High, Risk.None, "None. Requires a restart.",
                    "Open Start, type 'UAC' and open 'Change User Account Control settings'.",
                    "Move the slider to the default (second from top).",
                    "Click OK and restart the PC.").Link("UserAccountControlSettings.exe", "Open UAC settings");
            }
        }
    }
}
