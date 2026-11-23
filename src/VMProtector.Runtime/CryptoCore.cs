using System;

namespace VMProtector.Runtime
{
    internal static class CryptoCore
    {
        private static uint Rotl32(uint v, int n) => (v << n) | (v >> (32 - n));

        private static uint Load32(byte[] b, int o)
            => (uint)b[o] | ((uint)b[o + 1] << 8) | ((uint)b[o + 2] << 16) | ((uint)b[o + 3] << 24);

        private static void Store32(byte[] b, int o, uint v)
        {
            b[o] = (byte)(v & 0xFF);
            b[o + 1] = (byte)((v >> 8) & 0xFF);
            b[o + 2] = (byte)((v >> 16) & 0xFF);
            b[o + 3] = (byte)((v >> 24) & 0xFF);
        }

        private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = Rotl32(d, 16);
            c += d; b ^= c; b = Rotl32(b, 12);
            a += b; d ^= a; d = Rotl32(d, 8);
            c += d; b ^= c; b = Rotl32(b, 7);
        }

        public static byte[] ChaCha20Xor(byte[] key, byte[] nonce, uint counter, byte[] input)
        {
            byte[] output = new byte[input.Length];
            uint[] s = new uint[16];
            uint[] w = new uint[16];
            byte[] block = new byte[64];

            s[0] = 0x61707865u;
            s[1] = 0x3320646Eu;
            s[2] = 0x79622D32u;
            s[3] = 0x6B206574u;
            for (int i = 0; i < 8; i++) s[4 + i] = Load32(key, i * 4);
            s[13] = Load32(nonce, 0);
            s[14] = Load32(nonce, 4);
            s[15] = Load32(nonce, 8);

            int offset = 0;
            while (offset < input.Length)
            {
                s[12] = counter++;
                for (int i = 0; i < 16; i++) w[i] = s[i];
                for (int i = 0; i < 10; i++)
                {
                    QR(ref w[0], ref w[4], ref w[8], ref w[12]);
                    QR(ref w[1], ref w[5], ref w[9], ref w[13]);
                    QR(ref w[2], ref w[6], ref w[10], ref w[14]);
                    QR(ref w[3], ref w[7], ref w[11], ref w[15]);
                    QR(ref w[0], ref w[5], ref w[10], ref w[15]);
                    QR(ref w[1], ref w[6], ref w[11], ref w[12]);
                    QR(ref w[2], ref w[7], ref w[8], ref w[13]);
                    QR(ref w[3], ref w[4], ref w[9], ref w[14]);
                }
                for (int i = 0; i < 16; i++) Store32(block, i * 4, w[i] + s[i]);

                int chunk = input.Length - offset;
                if (chunk > 64) chunk = 64;
                for (int i = 0; i < chunk; i++)
                {
                    output[offset + i] = (byte)(input[offset + i] ^ block[i]);
                }
                offset += chunk;
            }

            Array.Clear(block, 0, block.Length);
            Array.Clear(w, 0, w.Length);
            Array.Clear(s, 0, s.Length);
            return output;
        }

        public static uint Crc32(byte[] data, int offset, int length)
        {
            uint crc = 0xFFFFFFFFu;
            for (int i = 0; i < length; i++)
            {
                crc ^= data[offset + i];
                for (int b = 0; b < 8; b++)
                {
                    uint mask = (uint)-(int)(crc & 1u);
                    crc = (crc >> 1) ^ (0xEDB88320u & mask);
                }
            }
            return ~crc;
        }

        public static ulong Fnv1a64(string text)
        {
            ulong h = 0xCBF29CE484222325UL;
            for (int i = 0; i < text.Length; i++)
            {
                char ch = text[i];
                if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + ('a' - 'A'));
                h ^= (byte)(ch & 0xFF);
                h *= 0x100000001B3UL;
            }
            return h;
        }
    }
}
