using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace VMProtector.Runtime
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint NativePicFn(ulong challenge);

    internal static class SecurityGuard
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool isDebuggerPresent);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            out IntPtr processInformation,
            int processInformationLength,
            out int returnLength);

        // Compiled MSVC /O2 /GS- x64 PIC NativeGuardCheck masked by 0x5A (Base64)
        private const string MaskedPicGuardX64B64 =
            "Etm2Uj8S0V5/OlpaWhLfmi9Q4lta94QS2Z5SmVXsClgfaZreiBLTRn4bVc+arNrmWlpaKi5XH2ma3ogbVc+aG9maWFVrHtGKEpu4ehLimZlmZgAA//8WUYgSaZIS4R1AQbnI4v0aH2mTE+FPJhAl4yNtxFVFGlo8VUXeWlpaWloSm5NjG9cLWxvRmxvZm1gTVfWZE1X1iRJpkhJxkRKbk2MSaZAScZEb2aN6KIkS0UZ+VWsSm7h6ElGYG9GKE3GY2ZBeEmfamZNbEtGbG1UcihKbsnoSaZvZuqpRmBLZnlKZ";

        // Blacklisted RE tool process names hashed with FNV1a-64 lowercase
        private static bool IsBlacklistedToolHash(ulong h) => h switch
        {
            0xDC7A757B79025A55UL or // dnspy
            0x55A776C6F47D61B5UL or // dnspy-x86
            0xD577664516A0E914UL or // ilspy
            0x5D614B1A59F97654UL or // x64dbg
            0xE3B2B1B7C5C88B14UL or // x32dbg
            0xB204A67C220143A1UL or // ida
            0x7D938B8BB8E6E463UL or // ida64
            0xA8C8D2A73AECE229UL or // ollydbg
            0x8151DFD18F452E31UL or // processhacker
            0x54487D8F11D51E83UL or // httpdebuggerui
            0x9C6B72EC9039CBFBUL or // fiddler
            0x7A57E3899038C6E3UL    // cheatengine-x86_64
                => true,
            _ => false
        };

        internal static volatile uint PoisonState;
        private static int _initialized;

        public static void Initialize() => Initialize(RuntimeConfig.GetSecurityFlags());

        public static void Initialize(int enabledFlags)
        {
            if (System.Threading.Interlocked.Exchange(ref _initialized, 1) != 0)
            {
                return;
            }

            uint flags = (uint)enabledFlags;
            uint poison = 0;

            if ((flags & 1u) != 0)
            {
                poison |= CheckManagedAndApiDebuggers();
                if (IntPtr.Size == 8)
                {
                    poison |= ExecuteNativePicGuard();
                }
            }

            if ((flags & 4u) != 0)
            {
                poison |= ScanAnalysisTools();
            }

            if (poison != 0)
            {
                PoisonState = poison ^ 0xA5A55A5Au;
                Environment.FailFast(string.Empty);
            }
        }

        private static uint CheckManagedAndApiDebuggers()
        {
            try
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    return 0x11u;
                }
                if (IsDebuggerPresent())
                {
                    return 0x12u;
                }
                if (CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, out bool remote) && remote)
                {
                    return 0x14u;
                }
                if (NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 7, out IntPtr port, IntPtr.Size, out _) == 0 && port != IntPtr.Zero)
                {
                    return 0x18u;
                }
                if (NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0x1E, out IntPtr obj, IntPtr.Size, out _) == 0 && obj != IntPtr.Zero)
                {
                    return 0x20u;
                }
            }
            catch
            {
            }
            return 0u;
        }

        private static uint ExecuteNativePicGuard()
        {
            IntPtr mem = IntPtr.Zero;
            try
            {
                byte[] plain = Convert.FromBase64String(MaskedPicGuardX64B64);
                int len = plain.Length;
                mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)len, 0x3000u, 0x04u); // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
                if (mem == IntPtr.Zero) return 0u;

                for (int i = 0; i < len; i++)
                {
                    plain[i] = (byte)(plain[i] ^ 0x5A);
                }
                Marshal.Copy(plain, 0, mem, len);
                Array.Clear(plain, 0, plain.Length);

                if (!VirtualProtect(mem, (UIntPtr)len, 0x20u, out _)) // PAGE_EXECUTE_READ
                {
                    return 0u;
                }

                var fn = Marshal.GetDelegateForFunctionPointer<NativePicFn>(mem);
                ulong challenge = 0x517CC1B727220A95UL ^ (ulong)Environment.TickCount;
                uint res = fn(challenge);

                uint expected = ComputeExpectedProof(challenge);
                if ((res & 0x0Fu) != 0 || (res & 0xFFFFFFF0u) != expected)
                {
                    return 0x40u;
                }
            }
            catch
            {
            }
            finally
            {
                if (mem != IntPtr.Zero)
                {
                    VirtualFree(mem, UIntPtr.Zero, 0x8000u); // MEM_RELEASE
                }
            }
            return 0u;
        }

        private static uint ComputeExpectedProof(ulong challenge)
        {
            ulong acc = challenge ^ 0xA5A55A5A3C3CC3C3UL;
            for (uint i = 0; i < 32; i++)
            {
                acc = ((acc << 7) | (acc >> 57)) ^ ((ulong)i * 0x9E3779B97F4A7C15UL);
                acc += 0xBF58476D1CE4E5B9UL;
            }
            return (uint)((acc ^ (acc >> 32)) & 0xFFFFFFF0UL);
        }

        private static uint ScanAnalysisTools()
        {
            try
            {
                Process[] procs = Process.GetProcesses();
                for (int i = 0; i < procs.Length; i++)
                {
                    try
                    {
                        string name = procs[i].ProcessName;
                        ulong h = CryptoCore.Fnv1a64(name);
                        if (IsBlacklistedToolHash(h))
                        {
                            return 0x80u;
                        }
                    }
                    catch { }
                    finally
                    {
                        procs[i].Dispose();
                    }
                }
            }
            catch
            {
            }
            return 0u;
        }
    }
}
