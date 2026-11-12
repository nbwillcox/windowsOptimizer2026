using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace WinOptimizer.Scanners
{
    /// <summary>Windows settings that affect speed, plus storage housekeeping. Read-only.</summary>
    internal static class SettingsScanner
    {
        const RegistryHive HKCU = RegistryHive.CurrentUser;
        const RegistryHive HKLM = RegistryHive.LocalMachine;
        const string Cat = "Windows settings";

        public static void Scan(ScanContext ctx)
        {
            var sys = ctx.Sys;
            bool w11 = sys.IsWin11;
            bool lowEnd = sys.RamGb < 8.5 || sys.SystemDriveIsSsd == false;

            // ---- Power plan
            const string pw = @"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes";
            string scheme = (Reg.GetStr(HKLM, pw, "ActivePowerScheme") ?? "").ToLowerInvariant();
            string overlay = (Reg.GetStr(HKLM, pw, sys.HasBattery ? "ActiveOverlayDcPowerScheme" : "ActiveOverlayAcPowerScheme") ?? "").ToLowerInvariant();
            string overlayAc = (Reg.GetStr(HKLM, pw, "ActiveOverlayAcPowerScheme") ?? "").ToLowerInvariant();
            bool saver = scheme == "a1841308-3541-4fab-bc81-f71556f20b4a" || overlayAc == "961cc777-2547-4f9d-8174-7d86181b8a7a";
            bool balanced = scheme == "381b4222-f694-41f0-9685-ff5bb260df2e" && overlayAc != "ded574b5-45a0-4f42-8737-46345c09c238";
            string powerWhere = w11 ? "Settings > System > Power & battery > Power mode" : "Control Panel > Hardware and Sound > Power Options";
            string[] powerSteps = w11
                ? new[] { "Open Settings (Win+I) > System > Power & battery.", "Set 'Power mode' to Best performance (when plugged in).", "To undo: set it back to Balanced." }
                : new[] { "Press Win+R, type powercfg.cpl and press Enter.", "Select 'High performance' (click 'Show additional plans' if hidden), or keep Balanced and move the battery-icon slider to Best performance.", "To undo: select Balanced again." };
            if (saver)
                ctx.Add(Cat, "Switch off the power-saving plan", "Windows is using a power-saving plan/mode.",
                    "Power saving deliberately limits processor speed. This is the most common reason a healthy PC feels slow.",
                    powerWhere, Difficulty.Easy, Impact.High, Risk.None, "None. Uses more electricity; on a laptop, battery life is shorter.", powerSteps).Link(w11 ? "ms-settings:powersleep" : "powercfg.cpl", "Open power settings");
            else if (balanced && !sys.HasBattery)
                ctx.Add(Cat, "Use the best-performance power mode", "This desktop PC is on the Balanced power plan.",
                    "Balanced lets the processor drop to low speeds and ramp up with a slight delay. A desktop has no battery to protect.",
                    powerWhere, Difficulty.Easy, Impact.Low, Risk.None, "None. Slightly higher electricity use and fan noise.", powerSteps).Link(w11 ? "ms-settings:powersleep" : "powercfg.cpl", "Open power settings");

            // ---- Visual effects
            int? fx = Reg.GetInt(HKCU, @"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting");
            if (fx != 2)
                ctx.Add(Cat, "Reduce animations and visual effects", "Windows animations and visual effects are enabled.",
                    "Window, menu and taskbar animations add a small delay to every action and use graphics resources. Turning them off makes the PC feel snappier, most noticeably on older hardware.",
                    "System Properties > Advanced > Performance Settings",
                    Difficulty.Easy, lowEnd ? Impact.Medium : Impact.Low, Risk.None, "Cosmetic only. Fully reversible.",
                    "Press Win+R, type sysdm.cpl and press Enter.",
                    "Open the Advanced tab and click Settings under Performance.",
                    "Choose 'Adjust for best performance', then re-tick 'Smooth edges of screen fonts' and 'Show thumbnails instead of icons' so text and pictures still look right.",
                    "Click OK. To undo: choose 'Let Windows choose what's best for my computer'.").Link("SystemPropertiesPerformance.exe", "Open Performance Options");

            if (Reg.GetInt(HKCU, @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency") == 1)
                ctx.Add(Cat, "Turn off transparency effects", "Transparency effects are on.",
                    "The see-through blur on the taskbar, Start menu and windows costs graphics power for no functional benefit.",
                    "Settings > Personalization > Colors", Difficulty.Easy, Impact.Low, Risk.None, "Cosmetic only.",
                    "Open Settings (Win+I) > Personalization > Colors.", "Turn 'Transparency effects' Off.").Link("ms-settings:colors", "Open Colors settings");

            // ---- Gaming
            if (Reg.GetInt(HKCU, @"Software\Microsoft\Windows\CurrentVersion\GameDVR", "HistoricalCaptureEnabled") == 1)
                ctx.Add(Cat, "Turn off background game recording", "Xbox Game Bar is set to record gameplay in the background.",
                    "Background recording continuously encodes video while you play, costing frame rate and disk writes.",
                    w11 ? "Settings > Gaming > Captures" : "Settings > Gaming > Captures", Difficulty.Easy, Impact.Medium, Risk.None,
                    "None. You can still record manually with Win+Alt+R.",
                    "Open Settings (Win+I) > Gaming > Captures.", "Turn off 'Record what happened' / 'Record in the background while I'm playing a game'.").Link("ms-settings:gaming-gamedvr", "Open Captures settings");

            if (Reg.GetInt(HKCU, @"Software\Microsoft\GameBar", "AutoGameModeEnabled") == 0)
                ctx.Add(Cat, "Turn Game Mode on", "Game Mode is switched off.",
                    "Game Mode stops Windows Update from installing drivers and showing restart prompts while you play, and gives the game priority.",
                    "Settings > Gaming > Game Mode", Difficulty.Easy, Impact.Low, Risk.None, "None.",
                    "Open Settings (Win+I) > Gaming > Game Mode.", "Turn Game Mode On.").Link("ms-settings:gaming-gamemode", "Open Game Mode settings");

            if (Reg.GetInt(HKLM, @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode") == 1)
                ctx.Add(Cat, "Enable hardware-accelerated GPU scheduling", "Your graphics driver supports hardware-accelerated GPU scheduling, but it is off.",
                    "It lets the graphics card manage its own work queue, which can reduce latency in games and video on a dedicated GPU.",
                    w11 ? "Settings > System > Display > Graphics > Change default graphics settings" : "Settings > System > Display > Graphics settings",
                    Difficulty.Easy, Impact.Low, Risk.Low,
                    "Rarely causes stutter or glitches with older drivers. If so, turn it back off. Requires a restart.",
                    "Open Settings (Win+I) > System > Display > Graphics" + (w11 ? " > Change default graphics settings." : " settings."),
                    "Turn on 'Hardware-accelerated GPU scheduling'.", "Restart the PC.").Link("ms-settings:display-advancedgraphics", "Open Graphics settings");

            // ---- Background apps (Windows 10 only; Windows 11 manages this per app)
            if (!w11 && Reg.GetInt(HKCU, @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled") != 1)
                ctx.Add(Cat, "Stop Store apps running in the background", "Microsoft Store apps are allowed to run in the background.",
                    "Apps such as Mail, Weather and Xbox keep refreshing when closed, using memory, CPU and battery.",
                    "Settings > Privacy > Background apps", Difficulty.Easy, Impact.Low, Risk.Low,
                    "Store apps (for example Mail or Calendar) will not show notifications or update live tiles until opened.",
                    "Open Settings (Win+I) > Privacy > Background apps.",
                    "Turn off 'Let apps run in the background', or switch off individual apps you do not need.").Link("ms-settings:privacy-backgroundapps", "Open Background apps");

            // ---- Suggestions / silently installed apps
            const string cdm = @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
            if (Reg.GetInt(HKCU, cdm, "SilentInstalledAppsEnabled") == 1 || Reg.GetInt(HKCU, cdm, "SubscribedContent-338388Enabled") == 1)
                ctx.Add(Cat, "Turn off Windows suggestions and promoted apps", "Windows is allowed to show suggestions and add promoted apps.",
                    "Suggested content downloads in the background and clutters the Start menu with apps you did not ask for.",
                    w11 ? "Settings > Personalization > Start, and Settings > System > Notifications" : "Settings > Personalization > Start",
                    Difficulty.Easy, Impact.Low, Risk.None, "None.",
                    w11 ? "Open Settings > Personalization > Start and turn off 'Show recommendations for tips, shortcuts, new apps, and more'."
                        : "Open Settings > Personalization > Start and turn off 'Show suggestions occasionally in Start'.",
                    "Open Settings > System > Notifications" + (w11 ? " > Additional settings" : " & actions") + " and untick the tips and suggestions options.").Link("ms-settings:personalization-start", "Open Start settings");

            // ---- Fast Startup
            if (Reg.GetInt(HKLM, @"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled") == 0)
                ctx.Add("Boot", "Turn on Fast Startup", "Fast Startup is off.",
                    "Fast Startup saves the Windows core to disk at shutdown so the next power-on is quicker, especially on hard disks.",
                    "Control Panel > Power Options > Choose what the power buttons do",
                    Difficulty.Easy, sys.SystemDriveIsSsd == false ? Impact.Medium : Impact.Low, Risk.Low,
                    "Leave it off if you dual-boot with another operating system or rely on Wake-on-LAN; it can interfere with both.",
                    "Press Win+R, type powercfg.cpl and press Enter.",
                    "Click 'Choose what the power buttons do', then 'Change settings that are currently unavailable'.",
                    "Tick 'Turn on fast startup (recommended)' and click Save changes.",
                    "If the option is missing, hibernation is disabled on this PC and Fast Startup is unavailable.")
                    .Link("control.exe|/name Microsoft.PowerOptions /page pageGlobalSettings", "Open power button settings");

            Storage(ctx);
        }

        static void Storage(ScanContext ctx)
        {
            var sys = ctx.Sys;
            bool w11 = sys.IsWin11;
            const string Cat = "Storage";

            if (sys.DiskTotal > 0)
            {
                double freePct = 100.0 * sys.DiskFree / sys.DiskTotal;
                if (freePct < 15)
                    ctx.Add(Cat, "Free up space on the system drive",
                        "The Windows drive has " + Util.Bytes(sys.DiskFree) + " free (" + freePct.ToString("0") + "%).",
                        "Windows needs free space for updates, the page file and temporary files. Below roughly 10-15% free, updates fail and performance drops.",
                        "Settings > System > Storage", Difficulty.Easy, freePct < 8 ? Impact.High : Impact.Medium, Risk.None,
                        "None when using Windows' own cleanup. Check the Downloads option before ticking it; it deletes your downloaded files.",
                        "Open Settings (Win+I) > System > Storage.",
                        "Open 'Temporary files' (or 'Cleanup recommendations' on Windows 11), tick what you do not need and click Remove files.",
                        "Uninstall programs you do not use and move large personal files (videos, photos) to another drive.").Link("ms-settings:storagesense", "Open Storage settings");
            }

            if (Reg.GetInt(HKCU, @"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy", "01") != 1)
                ctx.Add(Cat, "Turn on Storage Sense", "Storage Sense (automatic cleanup) is off.",
                    "It removes temporary files and old Recycle Bin contents automatically so the drive does not slowly fill up.",
                    "Settings > System > Storage", Difficulty.Easy, Impact.Low, Risk.None,
                    "None with default settings. Review its options if you keep files in the Recycle Bin or Downloads on purpose.",
                    "Open Settings (Win+I) > System > Storage.", "Turn Storage Sense On.",
                    "Click it to choose how often it runs and what it cleans.").Link("ms-settings:storagesense", "Open Storage settings");

            long temp = 0; bool partial = false;
            var sw = Stopwatch.StartNew();
            foreach (var dir in new[] { Path.GetTempPath(), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp") })
                temp += DirSize(dir, sw, ref partial);
            if (temp > 1L << 30)
                ctx.Add(Cat, "Clear temporary files",
                    "Temporary folders hold " + (partial ? "at least " : "") + Util.Bytes(temp) + ".",
                    "Leftover installer and app scratch files waste space and slow down scans and backups.",
                    "Settings > System > Storage > Temporary files, or Disk Cleanup (cleanmgr)", Difficulty.Easy, Impact.Low, Risk.None,
                    "None. Windows skips files that are still in use.",
                    "Close open programs.", "Open Settings (Win+I) > System > Storage > Temporary files.",
                    "Tick 'Temporary files' (leave Downloads unticked unless you are sure) and click Remove files.").Link("ms-settings:storagesense", "Open Storage settings");

            try
            {
                var rb = new Native.SHQUERYRBINFO { cbSize = System.Runtime.InteropServices.Marshal.SizeOf(typeof(Native.SHQUERYRBINFO)) };
                if (Native.SHQueryRecycleBin(null, ref rb) == 0 && rb.i64Size > 2L << 30)
                    ctx.Add(Cat, "Empty the Recycle Bin",
                        "The Recycle Bin holds " + Util.Bytes(rb.i64Size) + " in " + rb.i64NumItems + " items.",
                        "Deleted files still occupy disk space until the bin is emptied.",
                        "Recycle Bin on the desktop", Difficulty.Easy, Impact.Low, Risk.Low,
                        "No risk to Windows. Emptied files cannot be restored, so check the contents first.",
                        "Open the Recycle Bin and check nothing in it is still needed.", "Click 'Empty Recycle Bin'.").Link("shell:RecycleBinFolder", "Open Recycle Bin");
            }
            catch { }
        }

        /// <summary>Sums file sizes, giving up after a short time budget so the scan stays light.</summary>
        static long DirSize(string dir, Stopwatch sw, ref bool partial)
        {
            long total = 0;
            try
            {
                var stack = new System.Collections.Generic.Stack<string>();
                stack.Push(dir);
                while (stack.Count > 0)
                {
                    if (sw.ElapsedMilliseconds > 2500) { partial = true; break; }
                    string d = stack.Pop();
                    try
                    {
                        foreach (var f in new DirectoryInfo(d).EnumerateFiles()) total += f.Length;
                        foreach (var s in Directory.EnumerateDirectories(d)) stack.Push(s);
                    }
                    catch { }
                }
            }
            catch { }
            return total;
        }
    }
}
