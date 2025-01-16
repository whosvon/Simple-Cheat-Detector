// Windows only!
// Whosvon/PoppinTums

using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using Microsoft.Win32;
using System.Linq;
using System.Diagnostics;

namespace RegistryScanner
{
    class Program
    {
        static string outputFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "RegistryScannerResults.txt");

        static void Main(string[] args)
        {
            Console.WriteLine("Registry Scanner Tool\n");
            Console.WriteLine("Scanning for suspicious registry keys...\n");

            using (StreamWriter writer = new StreamWriter(outputFilePath))
            {
                writer.WriteLine("Registry Scanner Results\n");
                writer.WriteLine("Scanning for suspicious registry keys...\n");

                WriteSystemInfo(writer);

                List<string> registryPaths = new List<string>
                {
                    "HKEY_LOCAL_MACHINE\\Software",
                    "HKEY_CURRENT_USER\\Software",
                    "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services",
                    "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
                };

                foreach (var path in registryPaths)
                {
                    writer.WriteLine($"Scanning: {path}");
                    ScanRegistryPath(path, writer);
                }

                List<string> directoriesToScan = new List<string>
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Path.GetTempPath(),
                    GetDownloadsFolder()
                };

                foreach (var directory in directoriesToScan)
                {
                    writer.WriteLine($"Scanning directory: {directory}");
                    ScanDirectory(directory, writer);
                }

                writer.WriteLine("\nScanning Recycle Bin for deleted files...\n");
                ScanRecycleBin(writer);

                writer.WriteLine("\nScanning Prefetch for suspicious files...\n");
                ScanPrefetch(writer);

                writer.WriteLine("\nScan completed.");
            }

            Console.WriteLine($"\nScan completed. Results saved to: {outputFilePath}");
            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        static string GetDownloadsFolder() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        static void WriteSystemInfo(StreamWriter writer)
        {
            try
            {
                writer.WriteLine($"Last Boot Time: {GetLastBootTime()}");
                writer.WriteLine($"Last Reset Time: {GetLastResetTime()}");
            }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] Failed to get system info: {ex.Message}");
            }
        }

        static string GetLastBootTime() => GetSystemInfo("SELECT LastBootUpTime FROM Win32_OperatingSystem");

        static string GetLastResetTime() => GetSystemInfo("SELECT * FROM Win32_OperatingSystem");

        static string GetSystemInfo(string query)
        {
            try
            {
                var searcher = new ManagementObjectSearcher(query);
                var result = searcher.Get().Cast<ManagementBaseObject>().FirstOrDefault();

                if (result != null)
                {
                    DateTime bootTime = ManagementDateTimeConverter.ToDateTime(result["LastBootUpTime"].ToString());
                    return bootTime.ToString("yyyy-MM-dd HH:mm:ss");
                }
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }

            return "Unknown";
        }

        static RegistryKey GetBaseRegistryKey(string fullPath)
        {
            if (fullPath.StartsWith("HKEY_LOCAL_MACHINE"))
                return Registry.LocalMachine;
            else if (fullPath.StartsWith("HKEY_CURRENT_USER"))
                return Registry.CurrentUser;

            return null;
        }

        static void ScanRegistryPath(string path, StreamWriter writer)
        {
            try
            {
                RegistryKey baseKey = GetBaseRegistryKey(path);
                if (baseKey == null) return;

                string subKeyPath = path.Substring(baseKey.Name.Length + 1);
                using (RegistryKey key = baseKey.OpenSubKey(subKeyPath))
                {
                    if (key == null) return;

                    foreach (var valueName in key.GetValueNames())
                    {
                        string value = key.GetValue(valueName)?.ToString();
                        if (IsSuspicious(valueName, value))
                            writer.WriteLine($"[SUSPICIOUS] {path}\\{valueName} : {value}");
                    }
                }
            }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] Failed to scan {path}: {ex.Message}");
            }
        }

        static void ScanDirectory(string directory, StreamWriter writer)
        {
            try
            {
                if (!Directory.Exists(directory)) return;

                foreach (var file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories))
                {
                    CheckFile(file, writer);
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] Failed to scan directory {directory}: {ex.Message}");
            }
        }

        static void CheckFile(string filePath, StreamWriter writer)
        {
            try
            {
                FileInfo fileInfo = new FileInfo(filePath);

                if (IsSystemFile(filePath)) return;

                string fileDetails = $"{filePath} (Last Accessed: {fileInfo.LastAccessTime}, Created: {fileInfo.CreationTime})";

                if ((fileInfo.Attributes & FileAttributes.Hidden) != 0)
                    writer.WriteLine($"[HIDDEN] {fileDetails}");

                if (IsSuspicious(fileInfo.Name, fileInfo.FullName))
                    writer.WriteLine($"[SUSPICIOUS] {fileDetails}");

                LogFileOperations(fileInfo, writer);
            }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] Could not check file {filePath}: {ex.Message}");
            }
        }

        static void LogFileOperations(FileInfo fileInfo, StreamWriter writer)
        {
            try
            {
                if (!File.Exists(fileInfo.FullName) && fileInfo.CreationTime < DateTime.Now.AddDays(-1))
                    writer.WriteLine($"[DELETED] {fileInfo.FullName} (Deleted on: {fileInfo.CreationTime})");

                if (IsSuspicious(fileInfo.Name, fileInfo.FullName))
                    writer.WriteLine($"[RENAME] {fileInfo.FullName} (Renamed or suspiciously modified)");

                if (IsExecutable(fileInfo))
                    writer.WriteLine($"[EXECUTED] {fileInfo.FullName} (Executed on: {fileInfo.LastAccessTime})");
            }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] Could not log file operations for {fileInfo.FullName}: {ex.Message}");
            }
        }

        static bool IsExecutable(FileInfo fileInfo) => fileInfo.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase);

        static bool IsSuspicious(string name, string value)
        {
            string[] suspiciousKeywords = { "cheat", "hack", "inject", "bypass", "debugger", "fivem", "eulen", "red", "trainer", "exploit" };
            return suspiciousKeywords.Any(keyword =>
                (!string.IsNullOrEmpty(name) && name.Contains(keyword, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(value) && value.Contains(keyword, StringComparison.OrdinalIgnoreCase)));
        }

        static bool IsSystemFile(string filePath)
        {
            string[] systemDirectories = {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };

            if (systemDirectories.Any(dir => filePath.StartsWith(dir, StringComparison.OrdinalIgnoreCase)))
                return true;

            string[] systemFiles = { "explorer.exe", "svchost.exe", "lsass.exe", "taskmgr.exe", "msiexec.exe" };
            return systemFiles.Contains(Path.GetFileName(filePath), StringComparer.OrdinalIgnoreCase);
        }

        static void ScanRecycleBin(StreamWriter writer)
        {
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    string recycleBinPath = Path.Combine(drive.Name, "$Recycle.Bin");

                    if (Directory.Exists(recycleBinPath))
                    {
                        foreach (var deletedFile in Directory.GetFiles(recycleBinPath, "*", SearchOption.AllDirectories))
                        {
                            FileInfo fileInfo = new FileInfo(deletedFile);
                            if (IsSuspicious(fileInfo.Name, fileInfo.FullName))
                                writer.WriteLine($"[DELETED] {deletedFile} (Deleted on: {fileInfo.CreationTime})");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] Failed to scan the Recycle Bin: {ex.Message}");
            }
        }

        static void ScanPrefetch(StreamWriter writer)
        {
            try
            {
                string prefetchFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

                if (Directory.Exists(prefetchFolder))
                {
                    foreach (var prefetchFile in Directory.GetFiles(prefetchFolder, "*.pf"))
                    {
                        FileInfo fileInfo = new FileInfo(prefetchFile);
                        if (IsSuspicious(fileInfo.Name, fileInfo.FullName))
                            writer.WriteLine($"[PREFETCH] {prefetchFile} (Last Accessed: {fileInfo.LastAccessTime}, Created: {fileInfo.CreationTime})");
                    }
                }
            }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] Failed to scan the Prefetch folder: {ex.Message}");
            }
        }
    }
}
