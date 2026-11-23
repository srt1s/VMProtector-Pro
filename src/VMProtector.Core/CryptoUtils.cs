using System.Security.Cryptography;

namespace VMProtector.Core;

internal static class CryptoUtils
{
    public static byte[] RandomBytes(int count)
    {
        byte[] buf = new byte[count];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }

    public static int RandomInt()
    {
        Span<byte> buf = stackalloc byte[4];
        RandomNumberGenerator.Fill(buf);
        return BitConverter.ToInt32(buf);
    }

    private static uint Rotl32(uint v, int n) => (v << n) | (v >> (32 - n));

    private static uint Load32(ReadOnlySpan<byte> b, int o)
        => (uint)b[o] | ((uint)b[o + 1] << 8) | ((uint)b[o + 2] << 16) | ((uint)b[o + 3] << 24);

    private static void Store32(Span<byte> b, int o, uint v)
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

    public static byte[] ChaCha20Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, ReadOnlySpan<byte> input)
    {
        byte[] output = new byte[input.Length];
        Span<uint> s = stackalloc uint[16];
        Span<uint> w = stackalloc uint[16];
        Span<byte> block = stackalloc byte[64];

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

            int chunk = Math.Min(64, input.Length - offset);
            for (int i = 0; i < chunk; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ block[i]);
            }
            offset += chunk;
        }
        return output;
    }

    public static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        for (int i = 0; i < data.Length; i++)
        {
            crc ^= data[i];
            for (int b = 0; b < 8; b++)
            {
                uint mask = (uint)-(int)(crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
        return ~crc;
    }

    public static double CalculateShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;
        Span<int> counts = stackalloc int[256];
        for (int i = 0; i < data.Length; i++) counts[data[i]]++;

        double total = data.Length;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            int c = counts[i];
            if (c == 0) continue;
            double p = c / total;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static string RandomIdentifier(int len = 10)
    {
        const string firstChars = "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string restChars = "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Span<char> chars = stackalloc char[len];
        chars[0] = firstChars[RandomNumberGenerator.GetInt32(firstChars.Length)];
        for (int i = 1; i < len; i++)
        {
            chars[i] = restChars[RandomNumberGenerator.GetInt32(restChars.Length)];
        }
        return new string(chars);
    }
}
