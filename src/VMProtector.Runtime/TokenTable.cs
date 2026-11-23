using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace VMProtector.Runtime
{
    internal static class TokenTable
    {
        // Replaced completely by VMProtector.Core with real ldtoken-based array initialization
        public static Type[] Types = Array.Empty<Type>();
        public static MethodBase[] Methods = Array.Empty<MethodBase>();
        public static FieldInfo[] Fields = Array.Empty<FieldInfo>();

        private static int _ready;
        public static void EnsureInitialized()
        {
            if (System.Threading.Interlocked.Exchange(ref _ready, 1) == 0)
            {
                InitTokens();
            }
        }

        // Body replaced by VMProtector.Core using OpCodes.Ldtoken so ManagedPEImageBuilder updates tokens accurately
        public static void InitTokens() { }
    }
}
