using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using WinOptimizer.Scanners;

namespace WinOptimizer
{
    /// <summary>Runs every scanner in turn. Scanners only read; nothing on the PC is modified.</summary>
    internal static class ScanEngine
    {
        public const string RepoUrl = "https://github.com/nbwillcox/windowsOptimizer2026";

        public static ScanResult Run(IProgress<string> progress)
        {
            var sw = Stopwatch.StartNew();
            var ctx = new ScanContext();
            Step(progress, "Reading hardware and Windows details...", () => SystemScanner.Scan(ctx));
            Step(progress, "Checking startup programs...", () => StartupScanner.Scan(ctx));
            Step(progress, "Checking background services...", () => ServiceScanner.Scan(ctx));
            Step(progress, "Checking Windows settings and storage...", () => SettingsScanner.Scan(ctx));
            Step(progress, "Looking for programs that seem unused...", () => UnusedAppsScanner.Scan(ctx));
            return new ScanResult { Sys = ctx.Sys, Recs = ctx.Recs, When = DateTime.Now, Seconds = sw.Elapsed.TotalSeconds };
        }

        static void Step(IProgress<string> p, string message, Action a)
        {
            p?.Report(message);
            try { a(); } catch { /* a failed check is skipped; the rest of the scan continues */ }
        }

        public static List<KeyValuePair<string, string>> SummaryRows(SystemSummary s)
        {
            string drive = (s.SystemDriveIsSsd == true ? "SSD" : s.SystemDriveIsSsd == false ? "Hard disk" : "Drive") +
                           " · " + Util.Bytes(s.DiskFree) + " free of " + Util.Bytes(s.DiskTotal);
            string up = "Up " + (s.Uptime.TotalDays >= 1 ? (int)s.Uptime.TotalDays + " d " : "") + s.Uptime.Hours + " h" +
                        (s.BootSeconds.HasValue ? " · last boot " + s.BootSeconds.Value.ToString("0") + " s" : "");
            return new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("Windows", s.Os),
                new KeyValuePair<string, string>("Processor", s.Cpu + " · " + s.Threads + " threads"),
                new KeyValuePair<string, string>("Memory", s.RamGb.ToString("0.#") + " GB · " + s.MemLoad + "% in use"),
                new KeyValuePair<string, string>("System drive", drive),
                new KeyValuePair<string, string>("Graphics", s.Gpu),
                new KeyValuePair<string, string>("Running now", s.ProcessCount + " processes · " + s.StartupCount + " startup items · " + up),
            };
        }

        public static string BuildHtml(ScanResult r)
        {
            Func<string, string> e = WebUtility.HtmlEncode;
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>WinOptimizer report</title><style>")
              .Append("body{font-family:Segoe UI,Arial,sans-serif;background:#F4F5F7;color:#2F3542;max-width:900px;margin:24px auto;padding:0 16px}")
              .Append(".c{background:#fff;border:1px solid #E6E8EC;border-radius:10px;padding:16px;margin:0 0 12px}")
              .Append("h1{font-size:22px}h2{font-size:16px;margin:4px 0 8px}.m{color:#7A8394;font-size:12px}")
              .Append(".chip{display:inline-block;border-radius:10px;padding:2px 10px;font-size:12px;margin-right:6px;background:#ECEEF2}")
              .Append("table{border-collapse:collapse}td{padding:3px 14px 3px 0;vertical-align:top}li{margin:3px 0}")
              .Append("</style></head><body>");
            sb.Append("<h1>WinOptimizer report</h1><p class=\"m\">Scanned ").Append(e(r.When.ToString("f")))
              .Append(". This report is advice only. Nothing was changed on this PC. You act on it at your own risk.</p>");
            sb.Append("<div class=\"c\"><table>");
            foreach (var row in SummaryRows(r.Sys))
                sb.Append("<tr><td class=\"m\">").Append(e(row.Key)).Append("</td><td>").Append(e(row.Value)).Append("</td></tr>");
            sb.Append("</table></div>");

            foreach (var x in r.Recs.OrderByDescending(x => x.Score))
            {
                sb.Append("<div class=\"c\"><div class=\"m\">").Append(e(x.Category)).Append("</div><h2>").Append(e(x.Title)).Append("</h2>")
                  .Append("<span class=\"chip\">").Append(e(x.DifficultyText)).Append("</span>")
                  .Append("<span class=\"chip\">").Append(e(x.ImpactText)).Append("</span>")
                  .Append("<span class=\"chip\">").Append(e(x.RiskText)).Append("</span>")
                  .Append("<p>").Append(e(x.Finding)).Append("</p>");
                if (x.Items.Count > 0)
                {
                    sb.Append("<ul>");
                    foreach (var it in x.Items) sb.Append("<li>").Append(e(it)).Append("</li>");
                    sb.Append("</ul>");
                }
                sb.Append("<p><b>Why:</b> ").Append(e(x.Why)).Append("</p>")
                  .Append("<p><b>Where:</b> ").Append(e(x.Where)).Append("</p><ol>");
                foreach (var s in x.Steps) sb.Append("<li>").Append(e(s)).Append("</li>");
                sb.Append("</ol><p><b>If it goes wrong:</b> ").Append(e(x.RiskNote)).Append("</p></div>");
            }
            sb.Append("<p class=\"m\">Generated by WinOptimizer &middot; <a href=\"").Append(RepoUrl).Append("\">").Append(RepoUrl)
              .Append("</a> &middot; free for non-commercial use with a link back to the repository. No warranty; the author is not liable for any damage.</p>");
            sb.Append("</body></html>");
            return sb.ToString();
        }
    }
}
