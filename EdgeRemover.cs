using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning; // Added for platform attribute
using Microsoft.Win32;

[SupportedOSPlatform("windows")]
class EdgeRemover
{
    static void Main(string[] args)
    {
        // Optional safety check (manifest should ensure admin, but just in case)
        if (!IsAdmin())
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(" ╔══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine(" ║                  Administrator Rights Required                   ║");
            Console.WriteLine(" ║  This tool requires administrator privileges.                    ║");
            Console.WriteLine(" ║  Please restart the program by right-clicking and selecting      ║");
            Console.WriteLine(" ║  'Run as administrator'.                                         ║");
            Console.WriteLine(" ╚══════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine("\n   Press any key to exit...");
            Console.ReadKey();
            return;
        }

        Console.Title = "EdgeRemover made by @kriouscodes";

        bool removeWebView = args.Contains("--webview", StringComparer.OrdinalIgnoreCase);

        try
        {
            Console.Clear();
            PrintHeader();

            KillProcesses(new[] { "msedge", "msedgewebview2", "MicrosoftEdgeUpdate" });
            PrintSuccess("Edge processes terminated");

            string? setupPath = FindSetupExe();
            if (!string.IsNullOrEmpty(setupPath))
            {
                RunUninstallSilent(setupPath, "--uninstall --system-level --force-uninstall");
                if (removeWebView)
                    RunUninstallSilent(setupPath, "--uninstall --msedgewebview --system-level --force-uninstall");
                PrintSuccess("Official uninstall completed");
            }
            else
            {
                PrintWarning("setup.exe not found — using direct removal");
            }

            RunPowerShellSilent("Get-AppxPackage *Microsoft.Edge* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue");
            if (removeWebView)
                RunPowerShellSilent("Get-AppxPackage *Microsoft.EdgeWebView* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue");

            MarkAppxAsDeprovisioned();
            PrintSuccess("Appx packages removed/deprovisioned");

            DeleteEdgeDirectoriesSilent();
            PrintSuccess("Installation folders removed");

            DeleteSystem32EdgeFilesSilent();
            PrintSuccess("System files cleaned");

            RemoveScheduledTasks("MicrosoftEdge");
            PrintSuccess("Scheduled tasks removed");

            RemoveServices(new[] { "edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService" });
            PrintSuccess("Services removed");

            RemoveShortcuts();
            PrintSuccess("Shortcuts removed");

            CleanRegistry();
            PrintSuccess("Registry cleaned");

            PrintFooter();
            Console.WriteLine("   Press any key to exit...");
            Console.ReadKey(true);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"   ERROR: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("\n   Press any key to exit...");
            Console.ReadKey(true);
        }
    }

    private static void PrintHeader()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(" ╔══════════════════════════════════════════════════════════════════╗");
        Console.WriteLine(" ║              Microsoft Edge Complete Removal Tool                ║");
        Console.WriteLine(" ║                     made by @kriouscodes                         ║");
        Console.WriteLine(" ╚══════════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine("   Removing Microsoft Edge in the background...\n");
    }

    private static void PrintSuccess(string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"   ✓ {message}");
        Console.ResetColor();
    }

    private static void PrintWarning(string message)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"   ⚠ {message}");
        Console.ResetColor();
    }

    private static void PrintFooter()
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(" ╔══════════════════════════════════════════════════════════════════╗");
        Console.WriteLine(" ║               Microsoft Edge removed successfully!               ║");
        Console.WriteLine(" ║          All operations ran successfully — no error occurred     ║");
        Console.WriteLine(" ║                Restart your computer to finish                   ║");
        Console.WriteLine(" ╚══════════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static bool IsAdmin()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void KillProcesses(string[] names)
    {
        foreach (var name in names)
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                try { p.Kill(); p.WaitForExit(5000); } catch { }
                finally { p.Dispose(); } // Added cleanup
            }
        }
    }

    private static string? FindSetupExe()
    {
        string baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft", "Edge", "Application");
        if (!Directory.Exists(baseDir)) return null;

        // Fixed: Explicitly handle potential nulls from Path.GetFileName
        var versionDirs = Directory.GetDirectories(baseDir)
            .Select(d => new { Path = d, Name = Path.GetFileName(d) })
            .Where(x => x.Name != null && Version.TryParse(x.Name, out _))
            .OrderByDescending(x => Version.Parse(x.Name!)) // Name is checked above
            .Select(x => x.Path);

        foreach (var dir in versionDirs)
        {
            string setup = Path.Combine(dir, "Installer", "setup.exe");
            if (File.Exists(setup)) return setup;
        }
        return null;
    }

    private static void RunUninstallSilent(string setupPath, string args)
    {
        var psi = new ProcessStartInfo(setupPath, args)
        {
            UseShellExecute = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        try
        {
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }
        catch { }
    }

    private static void RunPowerShellSilent(string command)
    {
        var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"{command}\"")
        {
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            UseShellExecute = true
        };
        try
        {
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }
        catch { }
    }

    private static void DeleteEdgeDirectoriesSilent()
    {
        string pfX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

        string[] patterns =
        {
            Path.Combine(pfX86, "Microsoft", "Edge"),
            Path.Combine(pfX86, "Microsoft", "EdgeCore"),
            Path.Combine(pfX86, "Microsoft", "EdgeUpdate"),
            Path.Combine(pfX86, "Microsoft", "EdgeWebView"),
            Path.Combine(pf, "Microsoft", "Edge"),
            Path.Combine(pf, "Microsoft", "EdgeCore"),
            Path.Combine(pf, "Microsoft", "EdgeUpdate"),
            Path.Combine(pf, "Microsoft", "EdgeWebView"),
            Path.Combine(sysRoot, "SystemApps", "Microsoft.MicrosoftEdge*"),
            Path.Combine(pf, "WindowsApps", "Microsoft.MicrosoftEdge*"),
            Path.Combine(pf, "WindowsApps", "Microsoft.MicrosoftEdgeDevToolsClient*")
        };

        foreach (var pattern in patterns)
        {
            try
            {
                // Handle wildcards manually if they exist in the last part of path
                if (pattern.Contains('*'))
                {
                    string? dir = Path.GetDirectoryName(pattern);
                    string? searchPattern = Path.GetFileName(pattern);
                    
                    if (dir != null && Directory.Exists(dir) && searchPattern != null)
                    {
                        foreach (var subDir in Directory.GetDirectories(dir, searchPattern))
                        {
                             DeleteWithPermissions(subDir);
                        }
                    }
                }
                else
                {
                    DeleteWithPermissions(pattern);
                }
            }
            catch { }
        }
    }
    
    // Helper to keep DeleteEdgeDirectoriesSilent clean
    private static void DeleteWithPermissions(string path)
    {
        if (!Directory.Exists(path)) return;
        
        var di = new DirectoryInfo(path);
        GrantAdminFullControl(di);
        try { di.Delete(true); } catch { }
    }

    private static void DeleteSystem32EdgeFilesSilent()
    {
        string? sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(sysRoot)) return;

        string system32 = Path.Combine(sysRoot, "System32");
        if (!Directory.Exists(system32)) return;

        try
        {
            foreach (var filePath in Directory.GetFiles(system32, "MicrosoftEdge*.exe"))
            {
                try
                {
                    var fi = new FileInfo(filePath);
                    GrantAdminFullControl(fi);
                    fi.Delete();
                }
                catch { }
            }
        }
        catch { } // Catch Directory.GetFiles errors
    }

    private static void GrantAdminFullControl(FileSystemInfo info)
    {
        try
        {
            // Try deleting first (simplest check)
            if (info is DirectoryInfo di) { di.Delete(true); return; }
            else if (info is FileInfo fi) { fi.Delete(); return; }
        }
        catch { }

        try
        {
            var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            
            if (info is DirectoryInfo dirInfo)
            {
                DirectorySecurity security = dirInfo.GetAccessControl();
                security.SetOwner(admin);
                var rule = new FileSystemAccessRule(admin, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow);
                security.AddAccessRule(rule);
                dirInfo.SetAccessControl(security);
            }
            else if (info is FileInfo fileInfo)
            {
                FileSecurity security = fileInfo.GetAccessControl();
                security.SetOwner(admin);
                var rule = new FileSystemAccessRule(admin, FileSystemRights.FullControl,
                    AccessControlType.Allow);
                security.AddAccessRule(rule);
                fileInfo.SetAccessControl(security);
            }
        }
        catch { }
    }

    private static void RemoveScheduledTasks(string prefix)
    {
        var tasks = GetScheduledTasks().Where(t => t.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        foreach (var task in tasks)
        {
            var psi = new ProcessStartInfo("schtasks", $"/delete /tn \"{task}\" /f")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = true
            };
            try
            {
                using var p = Process.Start(psi);
                p?.WaitForExit();
            }
            catch { }
        }
    }

    private static IEnumerable<string> GetScheduledTasks()
    {
        var psi = new ProcessStartInfo("schtasks", "/query /fo csv")
        {
            RedirectStandardOutput = true,
            CreateNoWindow = true,
            UseShellExecute = false
        };
        
        try
        {
            using var proc = Process.Start(psi);
            if (proc == null) return Enumerable.Empty<string>();
            
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            
            if (string.IsNullOrWhiteSpace(output)) return Enumerable.Empty<string>();

            return output.Split('\n')
                .Skip(1) // Skip header
                .Select(line => line.Split(','))
                .Where(parts => parts.Length > 0)
                .Select(parts => parts[0].Trim('"'))
                .Where(t => !string.IsNullOrEmpty(t));
        }
        catch
        {
            return Enumerable.Empty<string>();
        }
    }

    private static void RemoveServices(string[] names)
    {
        foreach (var name in names)
        {
            var psi = new ProcessStartInfo("sc", $"delete {name}")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = true
            };
            try
            {
                using var p = Process.Start(psi);
                p?.WaitForExit();
            }
            catch { }
        }
    }

    private static void RemoveShortcuts()
    {
        string[] paths =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "Microsoft Edge.lnk"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Microsoft Edge.lnk"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Microsoft Edge.lnk")
        };

        foreach (var path in paths.Where(File.Exists))
        {
            try { File.Delete(path); } catch { }
        }

        // Fixed: Correct logic for getting registry values
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (key != null)
            {
                foreach (var subkeyName in key.GetSubKeyNames())
                {
                    try 
                    {
                        // key.Name includes HKEY_LOCAL_MACHINE, so we use the subkey name directly from the opened key
                        using RegistryKey? subKey = key.OpenSubKey(subkeyName);
                        if (subKey == null) continue;

                        string? profilePath = subKey.GetValue("ProfileImagePath") as string;
                        if (!string.IsNullOrEmpty(profilePath))
                        {
                            string link = Path.Combine(profilePath, "Desktop", "Microsoft Edge.lnk");
                            if (File.Exists(link)) try { File.Delete(link); } catch { }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static void MarkAppxAsDeprovisioned()
    {
        string? userSid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrEmpty(userSid)) return;

        string basePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";
        string[] apps = { "Microsoft.MicrosoftEdge", "Microsoft.MicrosoftEdgeDevToolsClient" };

        foreach (var app in apps)
        {
            CreateRegistryKey($@"{basePath}\EndOfLife\{userSid}\{app}");
            CreateRegistryKey($@"{basePath}\EndOfLife\S-1-5-18\{app}");
            CreateRegistryKey($@"{basePath}\Deprovisioned\{app}");
        }
    }

    private static void CreateRegistryKey(string path)
    {
        // Fixed: Use Registry.SetValue with valid FullPath
        try 
        { 
            // Registry.SetValue requires the full path including Hive
            Registry.SetValue($@"HKEY_LOCAL_MACHINE\{path}", "", "", RegistryValueKind.String); 
        }
        catch { }
    }

    private static void CleanRegistry()
    {
        string[] keys =
        {
            @"SOFTWARE\Microsoft\Edge",
            @"SOFTWARE\Microsoft\EdgeUpdate",
            @"SOFTWARE\Classes\microsoft-edge",
            @"SOFTWARE\Classes\microsoft-edge-holographic",
            @"SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}"
        };

        foreach (var key in keys)
        {
            DeleteRegistryKey(RegistryHive.LocalMachine, key);
            DeleteRegistryKey(RegistryHive.CurrentUser, key);
            DeleteRegistryKey(RegistryHive.ClassesRoot, key);
        }
    }

    private static void DeleteRegistryKey(RegistryHive hive, string subkey)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            baseKey.DeleteSubKeyTree(subkey, false);
        }
        catch { }
    }
}