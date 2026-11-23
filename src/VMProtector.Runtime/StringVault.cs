using System;
using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Text;

namespace VMProtector.Runtime
{
    internal static class StringVault
    {
        private static readonly ConcurrentDictionary<int, string> _cache = new ConcurrentDictionary<int, string>();
        private static byte[]? _plainBlob;
        private static int[]? _offsets;
        private static int[]? _lengths;
        private static readonly object _initLock = new object();

        private static void EnsureLoaded()
        {
            if (_plainBlob != null) return;
            lock (_initLock)
            {
                if (_plainBlob != null) return;
                SecurityGuard.Initialize(RuntimeConfig.GetSecurityFlags());

                string resName = RuntimeConfig.GetStringResource();
                Assembly asm = typeof(StringVault).Assembly;
                using Stream? s = asm.GetManifestResourceStream(resName);
                if (s == null)
                {
                    _plainBlob = Array.Empty<byte>();
                    _offsets = Array.Empty<int>();
                    _lengths = Array.Empty<int>();
                    return;
                }

                byte[] enc = new byte[s.Length];
                int read = 0;
                while (read < enc.Length)
                {
                    int n = s.Read(enc, read, enc.Length - read);
                    if (n <= 0) break;
                    read += n;
                }

                byte[] key = RuntimeConfig.GetStringKey();
                byte[] nonce = RuntimeConfig.GetStringNonce();
                uint poison = SecurityGuard.PoisonState;
                if (poison != 0 && key.Length > 0)
                {
                    key[0] ^= (byte)(poison & 0xFF);
                }

                byte[] dec = CryptoCore.ChaCha20Xor(key, nonce, 1u, enc);
                Array.Clear(key, 0, key.Length);

                using var ms = new MemoryStream(dec);
                using var br = new BinaryReader(ms, Encoding.UTF8);
                int count = br.ReadInt32();
                int[] offs = new int[count];
                int[] lens = new int[count];
                for (int i = 0; i < count; i++)
                {
                    offs[i] = br.ReadInt32();
                    lens[i] = br.ReadInt32();
                }
                int dataLen = br.ReadInt32();
                _plainBlob = br.ReadBytes(dataLen);
                _offsets = offs;
                _lengths = lens;
            }
        }

        public static string Get(int encodedId, int salt)
        {
            int id = encodedId ^ salt;
            if (_cache.TryGetValue(id, out string? cached))
            {
                return cached;
            }

            EnsureLoaded();
            if (_plainBlob == null || _offsets == null || _lengths == null || id < 0 || id >= _offsets.Length)
            {
                return string.Empty;
            }

            int off = _offsets[id];
            int len = _lengths[id];
            string value = len == 0 ? string.Empty : Encoding.UTF8.GetString(_plainBlob, off, len);
            _cache[id] = value;
            return value;
        }
    }
}
