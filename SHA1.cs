using System;
using System.Linq;
using System.IO;

namespace SecureHashAlgorithms
{
    class SHA1 : SHA
    {
        private readonly uint[] K = {
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x5a827999,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x6ed9eba1,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0x8f1bbcdc,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6,
            0xca62c1d6
        };
        private uint[] H;

        public SHA1()
        {
            outputLength = 160;
        }
        private uint Parity(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }
        private uint f(uint x, uint y, uint z, int i)
        {
            if (i <= 19)
                return Ch(x, y, z);
            if (i <= 39)
                return Parity(x, y, z);
            if (i <= 59)
                return Maj(x, y, z);
            if (i <= 79)
                return Parity(x, y, z);
            throw new("i is not valid");
        }

        protected override void UpdateHashValue(byte[] M)
        {
            var W = new uint[80];
            for (int i = 0; i < 16; i++)
                W[i] = BitConverter.ToUInt32(M.Skip(i * 4).Take(4).Reverse().ToArray());
            for (int i = 16; i < 80; i++)
                W[i] = (W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]).ROTL(1);

            uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
            for (int i = 0; i < 80; i++)
            {
                var T = a.ROTL(5) + f(b, c, d, i) + e + K[i] + W[i];
                e = d;
                d = c;
                c = b.ROTL(30);
                b = a;
                a = T;
            }
            H[0] = H[0] + a;
            H[1] = H[1] + b;
            H[2] = H[2] + c;
            H[3] = H[3] + d;
            H[4] = H[4] + e;
        }

        public override byte[] ComputeHash(Stream s)
        {
            int readLen = 0;
            ulong mLen = 0;
            var block = new byte[64];
            H = new uint[] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
            do
            {
                readLen = s.Read(block);
                mLen += (ulong)readLen * 8;
                if (mLen > ulong.MaxValue)
                    throw new("Input is too long.");
                if (readLen < 64)
                {
                    block[readLen] = 128;
                    for (int i = readLen + 1; i < 64; i++)
                        block[i] = 0;
                    var mLenArray = Convert.ToUInt64(mLen).GetBytes();
                    if (readLen * 8 + 1 > 448)
                    {
                        var lastblock = new byte[64];
                        mLenArray.CopyTo(lastblock, lastblock.Length - 8);
                        UpdateHashValue(block);
                        UpdateHashValue(lastblock);
                    }
                    else
                    {
                        mLenArray.CopyTo(block, block.Length - 8);
                        UpdateHashValue(block);
                    }
                }
                else
                {
                    UpdateHashValue(block);
                }
            } while (readLen == 64);
            return H.SelectMany(h => h.GetBytes()).ToArray();
        }
        public override byte[] ComputeHash(byte[] message)
        {
            if (message == null)
                message = new byte[0];
            var padded = Padding(message);
            var M = BlockDecomposition(padded);
            H = new uint[] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
            for (int i = 0; i < M.Count; i++)
            {
                UpdateHashValue(M[i]);
            }
            return H.SelectMany(h => h.GetBytes()).ToArray();
        }
    }
}