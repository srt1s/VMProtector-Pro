using VMProtector.Core;

namespace VMProtector.CLI;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return 0;
        }

        string cmd = args[0].ToLowerInvariant();
        if (cmd == "inspect")
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: vmp-cli inspect <input-file>");
                return 1;
            }
            return RunInspect(args[1]);
        }

        if (cmd == "protect")
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: vmp-cli protect <input-file> [options]");
                return 1;
            }
            return RunProtect(args[1..]);
        }

        // Direct shorthand: vmp-cli <file> [options]
        return RunProtect(args);
    }

    private static int RunInspect(string path)
    {
        try
        {
            BinaryInfo info = BinaryInspector.Inspect(path);
            Console.WriteLine($"File        : {info.FilePath}");
            Console.WriteLine($"Kind        : {info.Kind}");
            Console.WriteLine($"Architecture: {info.Architecture} ({info.Subsystem})");
            Console.WriteLine($"Size        : {info.FileSize:N0} bytes ({info.FileSize / 1048576.0:F2} MB)");
            Console.WriteLine($"Entropy     : {info.ShannonEntropy:F4} bits/byte");
            if (!string.IsNullOrEmpty(info.EntryAssemblyName))
            {
                Console.WriteLine($"Assembly    : {info.EntryAssemblyName} ({info.TargetFramework}, WPF={info.IsWpf})");
                Console.WriteLine($"Types       : {info.TotalTypes:N0} | Methods: {info.TotalMethods:N0} | VM Eligible: {info.EligibleVmMethods:N0}");
            }
            if (info.BundleFileCount > 0)
            {
                Console.WriteLine($"Bundle Files: {info.BundleFileCount}");
            }
            Console.WriteLine("Sections:");
            foreach (var s in info.Sections)
            {
                Console.WriteLine($"  {s.Name,-10} Raw={s.RawSize,9:N0}  Virt={s.VirtualSize,9:N0}  Entropy={s.Entropy:F4}");
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Inspect failed: {ex.Message}");
            return 1;
        }
    }

    private static int RunProtect(string[] args)
    {
        string input = args[0];
        string? output = null;
        var options = ProtectionOptions.FromPreset(ProtectionPreset.ToprakExternalMaximum);

        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "-o" or "--output":
                    if (i + 1 < args.Length) output = args[++i];
                    break;
                case "--preset":
                    if (i + 1 < args.Length)
                    {
                        options = args[++i].ToLowerInvariant() switch
                        {
                            "balanced" => ProtectionOptions.FromPreset(ProtectionPreset.BalancedSafe),
                            "max" or "maximum" => ProtectionOptions.FromPreset(ProtectionPreset.MaximumStealth),
                            "native" => ProtectionOptions.FromPreset(ProtectionPreset.NativePe64),
                            _ => ProtectionOptions.FromPreset(ProtectionPreset.ToprakExternalMaximum)
                        };
                    }
                    break;
                case "--no-vm": options.EnableMethodVirtualization = false; break;
                case "--no-strings": options.EnableStringEncryption = false; break;
                case "--no-cfg": options.EnableControlFlowObfuscation = false; break;
                case "--no-const": options.EnableConstantMutation = false; break;
                case "--no-rename": options.EnableSymbolRenaming = false; break;
                case "--no-antidebug": options.EnableAntiDebug = false; break;
                case "--no-stage2": options.EnableSingleFileStage2Loader = false; break;
                case "--tool-scan": options.EnableToolProcessScan = true; break;
                case "--max-vm":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int m)) options.MaxVirtualizedMethods = m;
                    break;
                case "--scope":
                    if (i + 1 < args.Length)
                    {
                        options.PriorityScopeFilters = args[++i]
                            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                            .ToList();
                    }
                    break;
            }
        }

        if (string.IsNullOrEmpty(output))
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(input)) ?? ".";
            string name = Path.GetFileNameWithoutExtension(input);
            string ext = Path.GetExtension(input);
            output = Path.Combine(dir, $"{name}_protected{ext}");
        }

        Console.WriteLine("============================================================");
        Console.WriteLine("  VMProtector-Pro v2.0 (ToprakExternal & Native PE64 Engine)");
        Console.WriteLine("============================================================");

        var pipeline = new ProtectorPipeline
        {
            OnProgress = (pct, msg) => Console.WriteLine($"[{pct * 100,5:F1}%] {msg}")
        };

        ProtectionReport r = pipeline.Protect(input, output, options);
        Console.WriteLine();
        if (!r.Success)
        {
            Console.Error.WriteLine($"[FAILED] {r.ErrorMessage}");
            return 2;
        }

        Console.WriteLine($"[SUCCESS] Protected in {r.Elapsed.TotalSeconds:F2}s");
        Console.WriteLine($"  Input        : {r.InputPath} ({r.InputSize:N0} B | {r.InputEntropy:F4} bits/B)");
        Console.WriteLine($"  Output       : {r.OutputPath} ({r.OutputSize:N0} B | {r.OutputEntropy:F4} bits/B)");
        Console.WriteLine($"  DetectedKind : {r.DetectedKind}");
        if (r.NativePe64Protected)
        {
            Console.WriteLine("  Native PE64  : C++20 Polymorphic Key VM + ChaCha20 + Reflective RAM Loader");
        }
        else
        {
            Console.WriteLine($"  VM Methods   : {r.VirtualizedMethods} virtualized ({r.SkippedVmMethods} skipped)");
            Console.WriteLine($"  Control Flow : {r.FlattenedMethods} methods flattened + opaque predicates");
            Console.WriteLine($"  Strings      : {r.EncryptedStrings} ChaCha20 encrypted");
            Console.WriteLine($"  Constants    : {r.MutatedConstants} mutated");
            Console.WriteLine($"  Renaming     : {r.RenamedTypes} types, {r.RenamedMethods} methods, {r.RenamedFields} fields");
            Console.WriteLine($"  Stage-2 RAM  : {r.Stage2InMemoryBundleApplied}");
        }

        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("VMProtector-Pro v2.0 CLI");
        Console.WriteLine("Commands:");
        Console.WriteLine("  vmp-cli inspect <input.exe>");
        Console.WriteLine("  vmp-cli protect <input.exe> [-o <out.exe>] [--preset toprak|balanced|max|native]");
        Console.WriteLine("Options:");
        Console.WriteLine("  --no-vm         Disable MSIL-to-VM virtualization");
        Console.WriteLine("  --no-strings    Disable ChaCha20 string vault");
        Console.WriteLine("  --no-cfg        Disable control-flow flattening");
        Console.WriteLine("  --no-const      Disable integer constant mutation");
        Console.WriteLine("  --no-rename     Disable WPF/BAML-safe symbol renaming");
        Console.WriteLine("  --no-antidebug  Disable managed + x64 PIC anti-debug injection");
        Console.WriteLine("  --no-stage2     Disable SingleFile encrypted RAM bootstrapper");
        Console.WriteLine("  --tool-scan     Enable running RE tool process scanner");
        Console.WriteLine("  --scope <a,b>   Prioritize VM virtualization for matching namespaces/types");
        Console.WriteLine("  --max-vm <N>    Cap max virtualized methods (default 1200)");
    }
}
