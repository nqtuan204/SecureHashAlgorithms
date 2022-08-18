using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.IO;

namespace SecureHashAlgorithms
{
    public abstract class SHA
    {
        protected int outputLength;
        public int OutputLength { get { return outputLength; } }
        public static SHA GetHashAlgorithm(HashAlgorithmName name)
        {
            if (name == HashAlgorithmName.SHA1)
                return new SHA1();
            if (name == HashAlgorithmName.SHA256)
                return new SHA256();
            if (name == HashAlgorithmName.SHA384)
                return new SHA384();
            if (name == HashAlgorithmName.SHA512)
                return new SHA512();
            throw new("algorithm name is not supported");
        }

        protected uint Ch(uint x, uint y, uint z)
        {
            return (x & y) ^ ((~x) & z);
        }

        protected ulong Ch(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ ((~x) & z);
        }

        protected uint Maj(uint x, uint y, uint z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        protected ulong Maj(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }
        protected ulong Sigma0(ulong x)
        {
            return x.ROTR(28) ^ x.ROTR(34) ^ x.ROTR(39);
        }

        protected ulong Sigma1(ulong x)
        {
            return x.ROTR(14) ^ x.ROTR(18) ^ x.ROTR(41);
        }

        protected ulong sigma0(ulong x)
        {
            return x.ROTR(1) ^ x.ROTR(8) ^ x.SHR(7);
        }

        protected ulong sigma1(ulong x)
        {
            return x.ROTR(19) ^ x.ROTR(61) ^ x.SHR(6);
        }
        protected virtual byte[] Padding(byte[] message)
        {
            int mLen = message.Length;
            int remain = mLen % 64;
            int len = mLen - remain + 64;
            if (remain * 8 + 1 > 448)
                len += 64;
            message = message.Concat(new byte[len - mLen]).ToArray();
            message[mLen] = 128;
            var last64bit = Convert.ToUInt64(mLen * 8).GetBytes();
            last64bit.CopyTo(message, message.Length - 8);
            return message;
        }

        protected virtual List<byte[]> BlockDecomposition(byte[] padded)
        {
            int N = padded.Length / 64;
            var M = new List<byte[]>(N);
            for (int i = 0; i < N; i++)
                M.Add(padded.Skip(i * 64).Take(64).ToArray());
            return M;
        }
        public abstract byte[] ComputeHash(byte[] message);
        public abstract byte[] ComputeHash(Stream s);
        protected abstract void UpdateHashValue(byte[] M);
    }
}
