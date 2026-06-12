using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace DPAPISnoop
{
    internal static class Helpers
    {
        internal static string ByteArrayToString(byte[] ba)
        {
            var hex = new StringBuilder(ba.Length * 2);
            foreach (var b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        internal static byte[] SubArray(byte[] src, int offset, int count)
        {
            var dst = new byte[count];
            Array.Copy(src, offset, dst, 0, count);
            return dst;
        }

        internal static int ReadInt32(byte[] data, int offset)
        {
            return BitConverter.ToInt32(data, offset);
        }

        internal static string ReadGuid(byte[] data, int offset)
        {
            var guidBytes = new byte[16];
            Array.Copy(data, offset, guidBytes, 0, 16);
            return new Guid(guidBytes).ToString("D");
        }

        internal static byte[] HexToBytes(string hex, string optionName, int expectedBytes)
        {
            if (hex.Length != expectedBytes * 2)
                throw new ArgumentException($"[!] {optionName} expects a {expectedBytes * 2}-char hex string");

            try
            {
                var bytes = new byte[expectedBytes];
                for (int i = 0; i < bytes.Length; i++)
                    bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                return bytes;
            }
            catch (FormatException)
            {
                throw new ArgumentException($"[!] {optionName} contains non-hex characters");
            }
        }

        internal static string RequireValue(string[] args, ref int i, string optionName)
        {
            if (i + 1 >= args.Length)
                throw new ArgumentException($"[!] {optionName} expects a value");
            return args[++i];
        }

        internal static byte[] Sha1Password(string password)
        {
            byte[] pw = Encoding.Unicode.GetBytes(password);
            using (var sha1 = SHA1.Create())
                return sha1.ComputeHash(pw);
        }

        internal static string ParseRpcSid(byte[] data, int offset, out int sidSize)
        {
            if (offset < 0 || offset + 8 > data.Length)
                throw new ArgumentException("[!] SID truncated before RPC_SID header");

            int revision = data[offset];
            int subCount = data[offset + 1];
            sidSize = 8 + subCount * 4;

            long idAuth = 0;
            for (int i = 0; i < 6; i++)
                idAuth = (idAuth << 8) | data[offset + 2 + i];

            var parts = new List<string> { "S", revision.ToString(), idAuth.ToString() };
            for (int i = 0; i < subCount; i++)
                parts.Add(BitConverter.ToUInt32(data, offset + 8 + i * 4).ToString());

            return string.Join("-", parts);
        }

        internal static string NormalizePath(string path)
        {
            path = path.Replace('/', '\\');
            return path.TrimEnd('\\');
        }
    }
}
