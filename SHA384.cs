using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Numerics;

namespace SecureHashAlgorithms
{
    class SHA384 : SHA
    {
        protected readonly ulong[] K = new ulong[]
        {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };
        protected ulong[] H;

        public SHA384()
        {
            outputLength = 384;
        }
        protected override byte[] Padding(byte[] message)
        {
            int mLen = message.Length;
            int remain = mLen % 128;
            int len = mLen - remain + 128;
            if (remain * 8 > 895)
                len += 128;
            message = message.Concat(new byte[len - mLen]).ToArray();
            message[mLen] = 128;
            // message < 3GB -> mLen < log(3*2^30) (bit) -> mLen < 24 (bit)
            var last32bit = Convert.ToUInt32(mLen * 8).GetBytes();
            last32bit.CopyTo(message, message.Length - 4);
            return message;
        }

        protected override void UpdateHashValue(byte[] M)
        {
            var W = new ulong[80];
            for (int i = 0; i < 16; i++)
                W[i] = BitConverter.ToUInt64(M.Skip(i * 8).Take(8).Reverse().ToArray());
            for (int i = 16; i < 80; i++)
                W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

            ulong a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
            for (int i = 0; i < 80; i++)
            {
                var T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
                var T2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }
            H[0] = H[0] + a;
            H[1] = H[1] + b;
            H[2] = H[2] + c;
            H[3] = H[3] + d;
            H[4] = H[4] + e;
            H[5] = H[5] + f;
            H[6] = H[6] + g;
            H[7] = H[7] + h;
        }

        protected override List<byte[]> BlockDecomposition(byte[] padded)
        {
            int N = padded.Length / 128;
            var M = new List<byte[]>(N);
            for (int i = 0; i < N; i++)
                M.Add(padded.Skip(i * 128).Take(128).ToArray());
            return M;
        }
        public override byte[] ComputeHash(byte[] message)
        {
            if (message == null)
                message = new byte[0];
            var padded = Padding(message);
            var M = BlockDecomposition(padded);
            H = new ulong[]{
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4
            };
            for (int i = 0; i < M.Count; i++)
                UpdateHashValue(M[i]);

            return H.Take(6).SelectMany(h => h.GetBytes()).ToArray();
        }

        public override byte[] ComputeHash(Stream s)
        {
            int readLen = 0;
            BigInteger limit = BigInteger.Pow(2, 128) - 1;
            BigInteger mLen = 0;
            var block = new byte[128];
            H = new ulong[]{
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4
            };
            do
            {
                readLen = s.Read(block);
                mLen += readLen * 8;
                if (mLen > limit)
                    throw new("Input is too long.");
                if (readLen < 128)
                {
                    block[readLen] = 128;
                    for (int i = readLen + 1; i < block.Length; i++)
                        block[i] = 0;
                    var mLenArray = mLen.ToByteArray(true, true);
                    if (readLen * 8 + 1 > 896)
                    {
                        var lastblock = new byte[128];
                        mLenArray.CopyTo(lastblock, lastblock.Length - mLenArray.Length);
                        UpdateHashValue(block);
                        UpdateHashValue(lastblock);
                    }
                    else
                    {
                        mLenArray.CopyTo(block, block.Length - mLenArray.Length);
                        UpdateHashValue(block);
                    }
                }
                else
                {
                    UpdateHashValue(block);
                }
            } while (readLen == 128);
            return H.Take(6).SelectMany(h => h.GetBytes()).ToArray();
        }
    }
}
