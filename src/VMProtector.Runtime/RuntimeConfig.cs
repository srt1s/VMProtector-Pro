using System;

namespace VMProtector.Runtime
{
    internal static class RuntimeConfig
    {
        public static string GetStringResource() => "__VMP_STR__";
        public static string GetVmResource() => "__VMP_VM__";
        public static string GetBootResource() => "__VMP_BOOT__";

        public static byte[] GetStringKey() => new byte[32];
        public static byte[] GetStringNonce() => new byte[12];

        public static byte[] GetVmKey() => new byte[32];
        public static byte[] GetVmNonce() => new byte[12];
        public static byte[] GetOpcodeMap() => new byte[256];

        public static byte[] GetBootKey() => new byte[32];
        public static byte[] GetBootNonce() => new byte[12];
        public static uint GetBootCrc() => 0u;

        public static int GetSecurityFlags() => 1;
    }
}
