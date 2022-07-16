using System.Linq;
using System.IO;
using System.Numerics;

namespace SecureHashAlgorithms
{
    class SHA512 : SHA384
    {
        public SHA512()
        {
            outputLength = 512;
        }
        public override byte[] ComputeHash(byte[] message)
        {
            if (message == null)
                message = new byte[0];
            var padded = Padding(message);
            var M = BlockDecomposition(padded);
            H = new ulong[]{
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
            };
            for (int i = 0; i < M.Count; i++)
            {
                UpdateHashValue(M[i]);

            }
            return H.SelectMany(h => h.GetBytes()).ToArray();
        }

        public override byte[] ComputeHash(Stream s)
        {
            int readLen = 0;
            BigInteger mLen = 0;
            BigInteger limit = BigInteger.Pow(2, 128) - 1;
            var block = new byte[128];
            H = new ulong[]{
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
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
            return H.SelectMany(h => h.GetBytes()).ToArray();
        }
    }
}
