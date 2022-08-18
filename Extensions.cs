using System;
using System.Linq;

namespace SecureHashAlgorithms
{
    public static class Extensions
    {
        public static byte[] GetBytes(this uint num)
        {
            var bytes = BitConverter.GetBytes(num).AsSpan();
            bytes.Reverse();
            return bytes.ToArray();
        }

        public static byte[] GetBytes(this ulong num)
        {
            var bytes = BitConverter.GetBytes(num).AsSpan();
            bytes.Reverse();
            return bytes.ToArray();
        }

        public static uint ROTL(this uint b, int n)
        {
            return (b << n) | (b >> (32 - n));
        }

        public static ulong ROTL(this ulong b, int n)
        {
            return (b << n) | (b >> (64 - n));
        }

        public static uint ROTR(this uint b, int n)
        {
            return (b >> n) | (b << (32 - n));
        }

        public static ulong ROTR(this ulong b, int n)
        {
            return (b >> n) | (b << (64 - n));
        }

        public static uint SHR(this uint b, int n)
        {
            return b >> n;
        }

        public static ulong SHR(this ulong b, int n)
        {
            return b >> n;
        }
    }
}
