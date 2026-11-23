using System.Diagnostics;
using System.Text;
using VMProtector.Core;

namespace VMProtector.Tests;

internal static class Program
{
    private static int Main()
    {
        Console.WriteLine("=== VMProtector-Pro v2.0 Automated Verification Suite ===");
        string root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        string scratch = Path.Combine(Path.GetTempPath(), "vmp_verify_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(scratch);

        try
        {
            TestDotNetSampleAndSingleFile(scratch);
            TestNativePe64(root, scratch);
            Console.WriteLine("\n[ALL VERIFICATION TESTS PASSED]");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"\n[TEST FAILED] {ex}");
            return 1;
        }
        finally
        {
            try { Directory.Delete(scratch, recursive: true); } catch { }
        }
    }

    private static void TestDotNetSampleAndSingleFile(string scratch)
    {
        Console.WriteLine("\n[1] Building .NET 8 sample app (VM math, loops, switch, arrays, objects, strings)...");
        string projDir = Path.Combine(scratch, "dotnet_sample");
        Directory.CreateDirectory(projDir);

        File.WriteAllText(Path.Combine(projDir, "SampleTarget.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType>
                <TargetFramework>net8.0</TargetFramework>
                <ImplicitUsings>enable</ImplicitUsings>
                <PublishSingleFile>true</PublishSingleFile>
                <SelfContained>true</SelfContained>
                <RuntimeIdentifier>win-x64</RuntimeIdentifier>
              </PropertyGroup>
            </Project>
            """);

        File.WriteAllText(Path.Combine(projDir, "Program.cs"), """
            using System;
            using System.Text;

            namespace SampleTarget;

            internal sealed class BoxedState
            {
                public int Counter;
                public string Label = "";
                public int Accumulate(int delta)
                {
                    Counter += delta;
                    return Counter * 3;
                }
            }

            internal static class LicenseCheckMock
            {
                public static readonly string SecretMarker = "SUPER_SECRET_TOPRAK_TOKEN_XYZ_987654";

                public static int ComputeMix(int a, long b, double c)
                {
                    int acc = 0;
                    for (int i = 0; i < 6; i++)
                    {
                        switch (i & 3)
                        {
                            case 0: acc += a ^ (int)b; break;
                            case 1: acc -= i * 7; break;
                            case 2: acc ^= (int)(c * 4.0); break;
                            default: acc += 13; break;
                        }
                    }
                    int[] arr = new int[4];
                    for (int j = 0; j < arr.Length; j++) arr[j] = acc + j;
                    return arr[2] + SecretMarker.Length;
                }
            }

            internal static class Program
            {
                private static int Main(string[] args)
                {
                    int mix = LicenseCheckMock.ComputeMix(42, 1337L, 3.5);
                    var st = new BoxedState { Label = "OK_STATE" };
                    int acc = st.Accumulate(15);
                    Console.WriteLine($"RESULT:{mix}:{acc}:{st.Label}:{LicenseCheckMock.SecretMarker}");
                    return mix == 0 ? 1 : 0;
                }
            }
            """);

        RunProcess("dotnet", $"build \"{projDir}\" -c Release -o \"{Path.Combine(projDir, "bin_dll")}\"", projDir, expectZero: true);
        string rawDll = Path.Combine(projDir, "bin_dll", "SampleTarget.dll");
        string outDll = Path.Combine(projDir, "bin_dll", "SampleTarget.vmp.dll");

        var pipeline = new ProtectorPipeline();
        var opt = ProtectionOptions.FromPreset(ProtectionPreset.ToprakExternalMaximum);
        opt.EnableSingleFileStage2Loader = false;
        ProtectionReport rDll = pipeline.Protect(rawDll, outDll, opt);
        if (!rDll.Success || rDll.VirtualizedMethods < 2 || rDll.EncryptedStrings < 1)
        {
            throw new Exception($"DLL protection failed: ok={rDll.Success} vm={rDll.VirtualizedMethods} str={rDll.EncryptedStrings} err={rDll.ErrorMessage}");
        }

        byte[] outDllBytes = File.ReadAllBytes(outDll);
        if (ContainsAsciiOrUtf16(outDllBytes, "SUPER_SECRET_TOPRAK_TOKEN_XYZ_987654"))
        {
            throw new Exception("Secret string leaked in protected DLL bytes!");
        }

        // Test executing the protected DLL via dotnet
        string origOutput = RunProcess("dotnet", $"\"{rawDll}\"", projDir, expectZero: true);
        File.Copy(
            Path.Combine(projDir, "bin_dll", "SampleTarget.runtimeconfig.json"),
            Path.Combine(projDir, "bin_dll", "SampleTarget.vmp.runtimeconfig.json"),
            overwrite: true);
        string protOutput = RunProcess("dotnet", $"\"{outDll}\"", projDir, expectZero: true);

        if (origOutput.Trim() != protOutput.Trim())
        {
            throw new Exception($"Protected DLL output mismatch!\nExpected: {origOutput}\nActual: {protOutput}");
        }
        Console.WriteLine($"  -> .NET DLL OK (VM={rDll.VirtualizedMethods}, CFG={rDll.FlattenedMethods}, Str={rDll.EncryptedStrings}, Out='{protOutput.Trim()}')");

        // Now test PublishSingleFile + Stage-2 In-Memory Bundle!
        Console.WriteLine("\n[2] Testing .NET 8 SingleFile Publish + Stage-2 In-Memory ChaCha20 Bundle...");
        string pubDir = Path.Combine(projDir, "pub");
        RunProcess("dotnet", $"publish \"{projDir}\" -c Release -r win-x64 -o \"{pubDir}\"", projDir, expectZero: true);
        string singleFileIn = Path.Combine(pubDir, "SampleTarget.exe");
        string singleFileOut = Path.Combine(scratch, "SampleTarget_SingleFile_VMP.exe");

        var sfOpt = ProtectionOptions.FromPreset(ProtectionPreset.ToprakExternalMaximum);
        ProtectionReport rSf = pipeline.Protect(singleFileIn, singleFileOut, sfOpt);
        if (!rSf.Success || !rSf.Stage2InMemoryBundleApplied)
        {
            throw new Exception($"SingleFile Stage-2 protection failed: {rSf.ErrorMessage}");
        }

        byte[] sfBytes = File.ReadAllBytes(singleFileOut);
        if (ContainsAsciiOrUtf16(sfBytes, "SUPER_SECRET_TOPRAK_TOKEN_XYZ_987654"))
        {
            throw new Exception("Secret string leaked in SingleFile VMP EXE!");
        }

        string sfOut = RunProcess(singleFileOut, "", scratch, expectZero: true);
        if (origOutput.Trim() != sfOut.Trim())
        {
            throw new Exception($"SingleFile VMP output mismatch!\nExpected: {origOutput}\nActual: {sfOut}");
        }
        Console.WriteLine($"  -> .NET 8 SingleFile Stage-2 OK (VM={rSf.VirtualizedMethods}, Str={rSf.EncryptedStrings}, Out='{sfOut.Trim()}')");
    }

    private static void TestNativePe64(string root, string scratch)
    {
        Console.WriteLine("\n[3] Testing C++20 Native PE64 Polymorphic Key VM + ChaCha20 + In-Memory Loader...");
        string vsWhere = @"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe";
        string vsPath = RunProcess(vsWhere, "-latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath", scratch, expectZero: true).Trim();
        string vcvars = Path.Combine(vsPath, @"VC\Auxiliary\Build\vcvars64.bat");

        string cppSrc = Path.Combine(scratch, "native_sample.cpp");
        File.WriteAllText(cppSrc, """
            #include <cstdio>
            #include <cstdint>
            int main() {
                const char* secret = "NATIVE_PE64_SECRET_BANNER_4242";
                uint64_t s = 0;
                for (int i = 0; i < 10; ++i) s += i * 7ULL;
                std::printf("NATIVE_OK:%s:%llu\n", secret, static_cast<unsigned long long>(s));
                return 42;
            }
            """);

        string nativeIn = Path.Combine(scratch, "native_sample.exe");
        string bat = Path.Combine(scratch, "build_sample.bat");
        File.WriteAllText(bat, $"@echo off\r\ncall \"{vcvars}\" >nul\r\ncl.exe /nologo /O2 /MT \"{cppSrc}\" /Fe:\"{nativeIn}\" /Fo:\"{scratch}\\ns.obj\"\r\n");
        RunProcess("cmd.exe", $"/c \"{bat}\"", scratch, expectZero: true);

        string nativeOut = Path.Combine(scratch, "native_sample_vmp.exe");
        var pipeline = new ProtectorPipeline();
        ProtectionReport r = pipeline.Protect(nativeIn, nativeOut, ProtectionOptions.FromPreset(ProtectionPreset.NativePe64));
        if (!r.Success || !r.NativePe64Protected)
        {
            throw new Exception($"Native PE64 protection failed: {r.ErrorMessage}");
        }

        byte[] protBytes = File.ReadAllBytes(nativeOut);
        if (ContainsAsciiOrUtf16(protBytes, "NATIVE_PE64_SECRET_BANNER_4242"))
        {
            throw new Exception("Native secret string leaked inside protected PE64!");
        }

        var psi = new ProcessStartInfo(nativeOut)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = scratch
        };
        using var proc = Process.Start(psi)!;
        string stdout = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 42 || !stdout.Contains("NATIVE_OK:NATIVE_PE64_SECRET_BANNER_4242:315"))
        {
            throw new Exception($"Native protected execution mismatch: exit={proc.ExitCode}, stdout='{stdout}'");
        }
        Console.WriteLine($"  -> Native PE64 OK (exit=42, entropy {r.InputEntropy:F3} -> {r.OutputEntropy:F3}, out='{stdout.Trim()}')");
    }

    private static bool ContainsAsciiOrUtf16(byte[] haystack, string needle)
    {
        byte[] a = Encoding.ASCII.GetBytes(needle);
        byte[] u = Encoding.Unicode.GetBytes(needle);
        return haystack.AsSpan().IndexOf(a) >= 0 || haystack.AsSpan().IndexOf(u) >= 0;
    }

    private static string RunProcess(string exe, string args, string cwd, bool expectZero)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            WorkingDirectory = cwd,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        using var p = Process.Start(psi)!;
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (expectZero && p.ExitCode != 0)
        {
            throw new Exception($"Command `{exe} {args}` failed ({p.ExitCode}):\n{stdout}\n{stderr}");
        }
        return stdout;
    }
}
