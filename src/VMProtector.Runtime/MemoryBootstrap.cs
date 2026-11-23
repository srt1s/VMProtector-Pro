using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;

namespace VMProtector.Runtime
{
    internal static class MemoryBootstrap
    {
        public static int Launch(string[] args)
        {
            SecurityGuard.Initialize(RuntimeConfig.GetSecurityFlags());

            string resName = RuntimeConfig.GetBootResource();
            Assembly hostAsm = typeof(MemoryBootstrap).Assembly;
            using Stream? s = hostAsm.GetManifestResourceStream(resName);
            if (s == null) return -1;

            byte[] enc = new byte[s.Length];
            int total = 0;
            while (total < enc.Length)
            {
                int n = s.Read(enc, total, enc.Length - total);
                if (n <= 0) break;
                total += n;
            }

            byte[] key = RuntimeConfig.GetBootKey();
            byte[] nonce = RuntimeConfig.GetBootNonce();
            uint poison = SecurityGuard.PoisonState;
            if (poison != 0 && key.Length > 0) key[0] ^= (byte)(poison & 0xFF);

            byte[] compressed = CryptoCore.ChaCha20Xor(key, nonce, 1u, enc);
            Array.Clear(key, 0, key.Length);

            uint expectedCrc = RuntimeConfig.GetBootCrc();
            if (expectedCrc != 0 && CryptoCore.Crc32(compressed, 0, compressed.Length) != expectedCrc)
            {
                return -2;
            }

            byte[] peBytes;
            using (var cms = new MemoryStream(compressed))
            using (var ds = new DeflateStream(cms, CompressionMode.Decompress))
            using (var outMs = new MemoryStream())
            {
                ds.CopyTo(outMs);
                peBytes = outMs.ToArray();
            }

            Assembly targetAsm = Assembly.Load(peBytes);
            string? targetSimpleName = targetAsm.GetName().Name;

            AppDomain.CurrentDomain.AssemblyResolve += (_, evArgs) =>
            {
                AssemblyName req = new AssemblyName(evArgs.Name);
                if (string.Equals(req.Name, targetSimpleName, StringComparison.OrdinalIgnoreCase))
                {
                    return targetAsm;
                }
                return null;
            };

            try
            {
                Type? appType = Type.GetType("System.Windows.Application, PresentationFramework");
                PropertyInfo? resAsmProp = appType?.GetProperty("ResourceAssembly", BindingFlags.Public | BindingFlags.Static);
                resAsmProp?.SetValue(null, targetAsm);
            }
            catch { }

            MethodInfo? ep = targetAsm.EntryPoint;
            if (ep == null) return -3;

            ParameterInfo[] epParams = ep.GetParameters();
            object?[] invokeArgs = epParams.Length == 0 ? Array.Empty<object?>() : new object?[] { args };
            object? ret = ep.Invoke(null, invokeArgs);
            return ret is int code ? code : 0;
        }
    }
}
