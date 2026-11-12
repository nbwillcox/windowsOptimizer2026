# WinOptimizer

A small, read-only performance advisor for Windows 10 and Windows 11.

It scans the PC, then lists what you could change to make it faster, where to change it, and a step-by-step walkthrough for each item. **It never changes anything itself.** No registry writes, no services touched, nothing uninstalled, no network access, no telemetry.

## What it checks

| Area | Examples |
| --- | --- |
| Hardware | RAM amount, SSD vs hard disk, free space, uptime, last boot time |
| Startup | Run keys and Startup folders, matched against a list of known programs |
| Services | Optional Windows services, plus third-party auto-start services |
| Windows settings | Power plan, visual effects, Game Mode/recording, background apps, Fast Startup, Storage Sense |
| Storage | Temporary files, Recycle Bin, low disk space |
| Unused programs | Installed programs with no sign of use for over a year (best effort, with a confidence level) |
| Security | Flags antivirus, firewall or UAC being off. Security software is never suggested for disabling or removal |

Every recommendation is rated three ways:

- **Difficulty**: Easy, Medium, Hard
- **Impact**: Low, Medium, High
- **Threat**: No damage threat, Low, Moderate, High, Could cripple Windows

## Running it

Requires Windows 10 or 11. Uses .NET Framework 4.8, which is already part of Windows, so there is nothing to install.

Run `WinOptimizer.exe`, accept the disclaimer, click **Scan this PC**. It runs as a standard user. Relaunching as administrator (optional button) makes boot timing and unused-program detection more accurate; it is still read-only.

**Save report** writes the results to an HTML file of your choosing. That is the only file the program ever writes.

## Building

Needs the .NET SDK (6 or later) on Windows.

```
dotnet build src/WinOptimizer -c Release
```

Output: `src/WinOptimizer/bin/Release/WinOptimizer.exe`

## About "unused programs"

Windows does not keep a reliable last-used date. WinOptimizer combines Explorer's launch history (UserAssist), Prefetch (administrator only) and file access times, and labels each result High, Medium or Low confidence. Treat the list as a prompt to check, not a verdict.

## Disclaimer

This software gives advice only. Any change you make is made by you, at your own risk. The author is not liable for any damage, data loss or other problem, whatever the cause. Back up your files and create a restore point before changing anything.

## License

Free for non-commercial use, provided you link back to this repository:
https://github.com/nbwillcox/windowsOptimizer2026

See [LICENSE](LICENSE).
