using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

using static DPAPISnoop.Dpapi;
using static DPAPISnoop.Helpers;

namespace DPAPISnoop
{
    sealed class CredhistRecord
    {
        public int Index;
        public CredhistEntry Entry;
    }

    sealed class CredhistEntry
    {
        public int Revision;
        public int Rounds;
        public int HashAlgo;
        public int CryptAlgo;
        public int ShaLen;
        public int NtLen;
        public byte[] Iv;
        public string Sid;
        public byte[] Encrypted;
    }

    sealed class CredhistDecryptionResult
    {
        public byte[] Sha1Previous;
        public byte[] NtlmPrevious;
    }

    internal static class Credhist
    {
        const int CredhistHeaderLen = 20;
        const int NextLenLen = 4;
        const int EntryTrailerLen = 20;

        static CredhistEntry ParseCredhistEntry(byte[] data)
        {
            if (data.Length < 64)
                throw new FormatException("[!] Invalid CREDHIST entry");

            int off = 0;
            int revision = ReadInt32(data, off); off += 4;
            int hashAlgo = ReadInt32(data, off); off += 4;
            int rounds = ReadInt32(data, off); off += 4;
            int sidLen = ReadInt32(data, off); off += 4;
            int cryptAlgo = ReadInt32(data, off); off += 4;
            int shaLen = ReadInt32(data, off); off += 4;
            int ntLen = ReadInt32(data, off); off += 4;

            var iv = SubArray(data, off, 16);
            off += 16;

            if ((hashAlgo != 0x8004 && hashAlgo != 0x8009 && hashAlgo != 0x800e) ||
                (cryptAlgo != 0x6603 && cryptAlgo != 0x6610) ||
                rounds <= 0 || shaLen != 20 || (ntLen != 16 && ntLen != 20) || sidLen < 8)
                throw new FormatException("[!] Unsupported CREDHIST entry");

            int sidSize;
            string sid = ParseRpcSid(data, off, out sidSize);
            if (sidSize != sidLen)
                throw new FormatException("[!] Invalid CREDHIST SID");
            off += sidSize;

            int blockSize = cryptAlgo == 0x6603 ? 8 : 16;
            int plainLen = shaLen + ntLen;
            int encLen = plainLen + ((blockSize - (plainLen % blockSize)) % blockSize);


            var encrypted = SubArray(data, off, encLen);
            off += encLen;
            ReadInt32(data, off); off += 4;
            ReadGuid(data, off); off += 16;

            if (off != data.Length)
                throw new FormatException("[!] Invalid CREDHIST entry length");

            return new CredhistEntry
            {
                Revision = revision,
                Rounds = rounds,
                HashAlgo = hashAlgo,
                CryptAlgo = cryptAlgo,
                ShaLen = shaLen,
                NtLen = ntLen,
                Iv = iv,
                Sid = sid,
                Encrypted = encrypted,
            };
        }

        static List<CredhistRecord> ParseCredhistFile(byte[] data)
        {
            if (data.Length < CredhistHeaderLen + NextLenLen)
                throw new FormatException("[!] Invalid CREDHIST file");

            var records = new List<CredhistRecord>();
            int end = data.Length;
            int entryIdx = 0;

            while (end >= NextLenLen)
            {
                int size = ReadInt32(data, end - NextLenLen);
                end -= NextLenLen;

                if (size == 0)
                    break;

                if (size < NextLenLen || end < size - NextLenLen)
                    throw new FormatException("[!] Invalid CREDHIST entry size");

                int entryLen = size - NextLenLen;
                int entryOffset = end - entryLen;
                var entryData = SubArray(data, entryOffset, entryLen);

                records.Add(new CredhistRecord
                {
                    Index = entryIdx,
                    Entry = ParseCredhistEntry(entryData),
                });

                end = entryOffset;
                entryIdx++;
            }

            if (end != CredhistHeaderLen)
                throw new FormatException("[!] Invalid CREDHIST header");

            return records;
        }

        static string FormatCredhistHash(CredhistEntry entry, string username)
        {
            string ivHex = ByteArrayToString(entry.Iv);
            string encHex = ByteArrayToString(entry.Encrypted);
            return $"{username}:$credhist$*{entry.Revision}*{entry.Sid}*0x{entry.HashAlgo:x4}*0x{entry.CryptAlgo:x4}*{entry.Rounds}*{ivHex}*{entry.ShaLen}*{entry.NtLen}*{encHex}";
        }

        internal static int DumpCredhistHashes(byte[] data, string username)
        {
            if (data.Length == 0)
            {
                Console.Error.WriteLine($"[*] CREDHIST file exists but is empty for {username}");
                return 0;
            }

            List<CredhistRecord> records;
            try
            {
                records = ParseCredhistFile(data);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[!] Failed to parse CREDHIST for {username}: {e.Message}");
                return 0;
            }

            foreach (var record in records)
            {
                string tag = record.Index == 0 ? "[current]" : $"[prev{record.Index}]";
                string labeledUser = $"{username}{tag}";
                Console.WriteLine(FormatCredhistHash(record.Entry, labeledUser));
            }

            if (records.Count == 0)
                Console.Error.WriteLine($"[*] CREDHIST file exists but contains no entries for {username} (no password changes recorded)");

            return records.Count;
        }

        internal static CredhistDecryptionResult TryDecryptCredhistEntry(CredhistEntry entry, byte[] sha1Pass)
        {
            byte[] sidBytes = Encoding.Unicode.GetBytes(entry.Sid + "\0");
            byte[] encKey;
            using (var hmac = new HMACSHA1(sha1Pass))
                encKey = hmac.ComputeHash(sidBytes);

            int dkLen = entry.CryptAlgo == 0x6603 ? 32 : 48;
            byte[] derived = DpapiPbkdf2(entry.HashAlgo, encKey, entry.Iv, entry.Rounds, dkLen);

            byte[] plain;
            try
            {
                if (entry.CryptAlgo == 0x6603)
                {
                    using (var des = TripleDES.Create())
                    {
                        des.Key = SubArray(derived, 0, 24);
                        des.IV = SubArray(derived, 24, 8);
                        des.Mode = CipherMode.CBC;
                        des.Padding = PaddingMode.None;
                        using (var dec = des.CreateDecryptor())
                            plain = dec.TransformFinalBlock(entry.Encrypted, 0, entry.Encrypted.Length);
                    }
                }
                else
                {
                    using (var aes = Aes.Create())
                    {
                        aes.Key = SubArray(derived, 0, 32);
                        aes.IV = SubArray(derived, 32, 16);
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.None;
                        using (var dec = aes.CreateDecryptor())
                            plain = dec.TransformFinalBlock(entry.Encrypted, 0, entry.Encrypted.Length);
                    }
                }
            }
            catch
            {
                return null;
            }

            int payloadLen = entry.ShaLen + entry.NtLen;
            for (int i = payloadLen; i < plain.Length; i++)
                if (plain[i] != 0) return null;

            var sha1Prev = SubArray(plain, 0, entry.ShaLen);
            var ntlmPrev = SubArray(plain, entry.ShaLen, entry.NtLen);
            if (ntlmPrev.Length > 16)
            {
                bool allNull = true;
                for (int i = 16; i < ntlmPrev.Length && allNull; i++)
                    if (ntlmPrev[i] != 0) allNull = false;
                if (allNull) ntlmPrev = SubArray(ntlmPrev, 0, 16);
            }

            return new CredhistDecryptionResult
            {
                Sha1Previous = sha1Prev,
                NtlmPrevious = ntlmPrev,
            };
        }

        internal static void WalkCredhistChain(byte[] data, string username, byte[] sha1Pass)
        {
            List<CredhistRecord> records;
            try
            {
                records = ParseCredhistFile(data);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[!] Failed to parse CREDHIST for {username}: {e.Message}");
                return;
            }

            if (records.Count == 0)
            {
                Console.Error.WriteLine($"[!] No CREDHIST entries found for {username}");
                return;
            }

            int startAt = -1;
            for (int i = 0; i < records.Count; i++)
            {
                if (TryDecryptCredhistEntry(records[i].Entry, sha1Pass) != null)
                {
                    startAt = i;
                    break;
                }
            }

            if (startAt < 0)
            {
                Console.Error.WriteLine($"[!] No CREDHIST entries decrypted for {username} - provided password does not match any entry");
                return;
            }

            if (startAt > 0)
                Console.Error.WriteLine($"[!] {username}: skipped {startAt} newer entr{(startAt == 1 ? "y" : "ies")} (current password unknown); chain walk starts at entry {startAt}");

            byte[] curSha1 = sha1Pass;
            int decrypted = 0;
            for (int i = startAt; i < records.Count; i++)
            {
                var record = records[i];
                var result = TryDecryptCredhistEntry(record.Entry, curSha1);
                if (result == null)
                {
                    Console.Error.WriteLine($"[!] Chain broken at CREDHIST entry {record.Index} of {username}");
                    break;
                }

                var sha1Prev = result.Sha1Previous;
                var ntlmPrev = result.NtlmPrevious;
                Console.WriteLine($"{username}:CREDHIST entry {record.Index} NTLM:{ByteArrayToString(ntlmPrev)}  sha1:{ByteArrayToString(sha1Prev)}");
                curSha1 = sha1Prev;
                decrypted++;
            }

            if (decrypted == 0)
                Console.Error.WriteLine($"[!] No CREDHIST entries decrypted for {username}");
        }
    }
}
