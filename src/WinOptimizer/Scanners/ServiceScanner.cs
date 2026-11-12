using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Win32;

namespace WinOptimizer.Scanners
{
    /// <summary>Looks at Windows services that start automatically. Read-only.</summary>
    internal static class ServiceScanner
    {
        class Known
        {
            public string Name, Why, RiskNote; public Impact I; public Risk R; public string Cat = "Services";
            public Func<ScanContext, bool> When = c => true;
        }

        static readonly Known[] Kb =
        {
            new Known { Name = "DiagTrack", I = Impact.Low, R = Risk.Low,
                Why = "Collects usage and diagnostic data and sends it to Microsoft in the background, using some CPU, disk and network.",
                RiskNote = "Windows keeps working. Some feedback/diagnostic features and Windows Insider builds depend on it." },
            new Known { Name = "dmwappushservice", I = Impact.Low, R = Risk.Low,
                Why = "Routes telemetry messages. Not needed on a home PC.",
                RiskNote = "Windows keeps working. Only matters on PCs managed by an organisation." },
            new Known { Name = "Fax", I = Impact.Low, R = Risk.None,
                Why = "Only needed to send or receive faxes through a fax modem.",
                RiskNote = "None unless you actually fax from this PC." },
            new Known { Name = "MapsBroker", I = Impact.Low, R = Risk.None,
                Why = "Updates offline maps for the Windows Maps app in the background.",
                RiskNote = "Only offline maps stop updating." },
            new Known { Name = "RetailDemo", I = Impact.Low, R = Risk.None,
                Why = "Store display mode. Never needed on a personal PC.",
                RiskNote = "None." },
            new Known { Name = "WMPNetworkSvc", I = Impact.Low, R = Risk.None,
                Why = "Shares Windows Media Player libraries to other devices on the network.",
                RiskNote = "Only media sharing from Windows Media Player stops." },
            new Known { Name = "XblAuthManager", I = Impact.Low, R = Risk.Low,
                Why = "Xbox Live sign-in. Only useful if you use the Xbox app, Game Pass or Microsoft Store games.",
                RiskNote = "Xbox app, Game Pass and some Store games will not sign in until it is set back." },
            new Known { Name = "XblGameSave", I = Impact.Low, R = Risk.Low,
                Why = "Syncs Xbox Live game saves. Only useful for Xbox / Game Pass games.",
                RiskNote = "Cloud saves for Xbox / Game Pass games stop syncing." },
            new Known { Name = "XboxNetApiSvc", I = Impact.Low, R = Risk.Low,
                Why = "Xbox Live networking. Only useful for Xbox / Game Pass multiplayer.",
                RiskNote = "Xbox Live multiplayer may not connect." },
            new Known { Name = "RemoteRegistry", I = Impact.Low, R = Risk.None, Cat = "Security",
                Why = "Lets other computers on the network edit this PC's registry. Home PCs do not need it, and turning it off reduces attack surface.",
                RiskNote = "None on a home PC. Some corporate management tools need it." },
            new Known { Name = "WSearch", I = Impact.Medium, R = Risk.Moderate,
                When = c => c.Sys.SystemDriveIsSsd == false,
                Why = "Indexing keeps a hard disk busy for long periods. On an HDD this is often the cause of constant disk activity.",
                RiskNote = "Start menu, File Explorer and Outlook searches become much slower or incomplete. Not recommended on SSD systems. Fully reversible." },
            new Known { Name = "SysMain", I = Impact.Medium, R = Risk.Low,
                When = c => c.Sys.SystemDriveIsSsd == false && c.Sys.RamGb < 8.5,
                Why = "Preloads apps into memory. On a PC with a hard disk and little RAM it can cause long bursts of 100% disk use.",
                RiskNote = "Apps may open slightly slower. Leave it on for SSD systems, where it helps." },
            new Known { Name = "Spooler", I = Impact.Low, R = Risk.Low,
                When = c => !HasRealPrinter(),
                Why = "Only needed for printing. No real printer is installed on this PC, and the spooler has a history of security vulnerabilities.",
                RiskNote = "Printing and 'Print to PDF' stop working until it is set back to Automatic." },
        };

        static bool HasRealPrinter()
        {
            try
            {
                using (var k = Reg.Open(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Print\Printers"))
                {
                    if (k == null) return true;
                    return k.GetSubKeyNames().Any(n => !Util.ContainsAny(n, "Microsoft Print to PDF", "XPS Document Writer", "Fax", "OneNote"));
                }
            }
            catch { return true; }
        }

        public static void Scan(ScanContext ctx)
        {
            ServiceController[] all;
            try { all = ServiceController.GetServices(); } catch { return; }

            var thirdParty = new List<string>();
            try
            {
                foreach (var sc in all)
                {
                    ServiceStartMode mode; ServiceControllerStatus status; string display;
                    try { mode = sc.StartType; status = sc.Status; display = sc.DisplayName; }
                    catch { continue; }

                    bool auto = mode == ServiceStartMode.Automatic;
                    bool running = status == ServiceControllerStatus.Running;

                    var k = Kb.FirstOrDefault(x => x.Name.Equals(sc.ServiceName, StringComparison.OrdinalIgnoreCase));
                    if (k != null)
                    {
                        if ((auto || running) && k.When(ctx))
                        {
                            ctx.Add(k.Cat, "Set the \"" + display + "\" service to Manual",
                                "Service \"" + display + "\" (" + sc.ServiceName + ") is " +
                                (running ? "running" : "not running") + ", startup type " + mode + ".",
                                k.Why, "Services console (services.msc)",
                                Difficulty.Medium, k.I, k.R, k.RiskNote,
                                "Press Win+R, type services.msc and press Enter (administrator rights are required).",
                                "Find \"" + display + "\" in the list and double-click it.",
                                "Set 'Startup type' to Manual (safer than Disabled), click Stop, then OK.",
                                "To undo: set 'Startup type' back to Automatic and click Start.").Link("services.msc", "Open Services");
                        }
                        continue;
                    }

                    if (auto && running)
                    {
                        string company = Company(sc.ServiceName);
                        if (company != null && !Util.ContainsAny(company, "Microsoft") &&
                            !Util.ContainsAny(display + " " + company + " " + sc.ServiceName, Util.SecurityWords))
                            thirdParty.Add(company + "\u0001" + display);
                    }
                }
            }
            finally { foreach (var sc in all) sc.Dispose(); }

            if (thirdParty.Count > 0)
            {
                thirdParty.Sort(StringComparer.OrdinalIgnoreCase);
                var rec = ctx.Add("Services", "Review " + thirdParty.Count + " non-Microsoft background services",
                    "These third-party services start automatically and are running now (grouped by publisher):",
                    "Installed programs often add always-on services (updaters, launchers, helper tools). Each uses memory and adds to boot time. Ones belonging to software you rarely use can be set to Manual. Security software has been left out of this list on purpose.",
                    "Services console (services.msc), or uninstall the parent program if unused",
                    Difficulty.Hard, Impact.Medium, Risk.High,
                    "Judge each one individually. Updater and launcher services are safe to set to Manual. Do NOT change services from hardware vendors (Intel, AMD, NVIDIA, Realtek, your PC maker) unless you know what they do: disabling a driver service can break audio, graphics, networking or, in the worst case, stop Windows from starting properly.",
                    "Press Win+R, type services.msc and press Enter.",
                    "For each service listed, search its name online to learn what it does.",
                    "If it belongs to software you do not use, uninstall that software instead (cleanest option).",
                    "Otherwise double-click it and set 'Startup type' to Manual. Change one at a time and restart to confirm nothing broke.",
                    "To undo: set 'Startup type' back to Automatic.").Link("services.msc", "Open Services");
                // Sorted by publisher (the part before the separator), shown as "Service - Publisher".
                rec.Items = thirdParty.Select(t => t.Split('\u0001')).Select(p => p[1] + "  —  " + p[0]).ToList();
            }
        }

        /// <summary>Company name from the service executable's version info, or null if it is hosted by Windows itself.</summary>
        static string Company(string serviceName)
        {
            try
            {
                string image = Reg.GetStr(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\" + serviceName, "ImagePath");
                string exe = Util.ExtractExe(image);
                if (exe == null || exe.IndexOf("svchost.exe", StringComparison.OrdinalIgnoreCase) >= 0) return null;
                if (!File.Exists(exe)) return null;
                string c = FileVersionInfo.GetVersionInfo(exe).CompanyName;
                return string.IsNullOrWhiteSpace(c) ? "unknown publisher" : c.Trim();
            }
            catch { return null; }
        }
    }
}
