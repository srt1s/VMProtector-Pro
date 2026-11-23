using System.Diagnostics;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Bundles;
using AsmResolver.IO;
using AsmResolver.PE.Builder;
using VMProtector.Core.Passes;

namespace VMProtector.Core;

public sealed class ProtectorPipeline
{
    public Action<double, string>? OnProgress { get; set; }

    private void Report(double pct, string msg) => OnProgress?.Invoke(pct, msg);

    public ProtectionReport Protect(string inputPath, string outputPath, ProtectionOptions options)
    {
        var sw = Stopwatch.StartNew();
        var report = new ProtectionReport
        {
            InputPath = inputPath,
            OutputPath = outputPath
        };

        try
        {
            Report(0.05, "Analyzing target binary...");
            BinaryInfo info = BinaryInspector.Inspect(inputPath);
            report.DetectedKind = info.Kind;
            report.InputSize = info.FileSize;
            report.InputEntropy = info.ShannonEntropy;

            string? outDir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
            if (!string.IsNullOrEmpty(outDir)) Directory.CreateDirectory(outDir);

            switch (info.Kind)
            {
                case BinaryKind.DotNetSingleFileBundle:
                    ProtectSingleFileBundle(inputPath, outputPath, options, report);
                    break;

                case BinaryKind.DotNetAssembly:
                    byte[] inputBytes = File.ReadAllBytes(inputPath);
                    byte[] protectedBytes = ProtectDotNetModuleBytes(inputBytes, options, report, isSingleFileEntry: false);
                    File.WriteAllBytes(outputPath, protectedBytes);
                    break;

                case BinaryKind.NativePe64:
                    Report(0.30, "Compiling C++20 Polymorphic Key VM & ChaCha20 Native PE64 payload...");
                    NativePeProtector.ProtectNativePe64(inputPath, outputPath, options);
                    report.NativePe64Protected = true;
                    break;

                default:
                    throw new NotSupportedException("Unsupported binary format. Expected .NET 8 / Framework PE or x64 Native PE.");
            }

            byte[] outBytes = File.ReadAllBytes(outputPath);
            report.OutputSize = outBytes.Length;
            report.OutputEntropy = CryptoUtils.CalculateShannonEntropy(outBytes);
            report.Success = true;
            Report(1.0, "Protection pipeline completed successfully.");
        }
        catch (Exception ex)
        {
            report.Success = false;
            report.ErrorMessage = ex.Message;
            Report(1.0, $"Error: {ex.Message}");
        }
        finally
        {
            sw.Stop();
            report.Elapsed = sw.Elapsed;
        }

        return report;
    }

    private void ProtectSingleFileBundle(string inputPath, string outputPath, ProtectionOptions options, ProtectionReport report)
    {
        Report(0.10, "Unpacking .NET SingleFile bundle manifest...");
        byte[] rawHostAndBundle = File.ReadAllBytes(inputPath);
        var manifest = BundleManifest.FromDataSource(new ByteArrayDataSource(rawHostAndBundle));

        BundleFile? entryFile = BinaryInspector.FindEntryAssemblyBundleFile(manifest)
            ?? throw new InvalidOperationException("Unable to locate managed entry assembly inside SingleFile bundle.");

        Report(0.18, $"Extracted entry assembly: {entryFile.RelativePath}");
        byte[] originalEntryBytes = entryFile.GetData();

        // Protect entry assembly in-place (Stage 1: VM Virtualization + Strings + CFG + Constants + Renaming + Anti-Debug)
        byte[] protectedEntryBytes = ProtectDotNetModuleBytes(originalEntryBytes, options, report, isSingleFileEntry: true);

        byte[] finalBundleAssemblyBytes = protectedEntryBytes;
        if (options.EnableSingleFileStage2Loader)
        {
            Report(0.84, "Building Stage-2 In-Memory ChaCha20 Bootstrapper (Anti-SingleFileExtractor)...");
            finalBundleAssemblyBytes = SingleFileStage2Builder.BuildStage2LoaderAssembly(
                originalEntryBytes,
                protectedEntryBytes,
                options);
            report.Stage2InMemoryBundleApplied = true;
        }

        int entryIndex = manifest.Files.IndexOf(entryFile);
        bool wasCompressed = entryFile.IsCompressed;
        string relPath = entryFile.RelativePath;
        BundleFileType fileType = entryFile.Type;

        var replacementFile = new BundleFile(relPath, fileType, finalBundleAssemblyBytes);
        if (wasCompressed)
        {
            replacementFile.Compress();
        }
        manifest.Files[entryIndex] = replacementFile;

        Report(0.92, "Re-packing .NET SingleFile bundle with preserved apphost & Win32 resources...");
        BundlerParameters bundlerParams = BundlerParameters.FromExistingBundle(
            rawHostAndBundle,
            relPath);

        manifest.WriteUsingTemplate(outputPath, bundlerParams);
    }

    private byte[] ProtectDotNetModuleBytes(
        byte[] moduleBytes,
        ProtectionOptions options,
        ProtectionReport report,
        bool isSingleFileEntry)
    {
        ModuleDefinition module = ModuleDefinition.FromBytes(moduleBytes);

        Report(0.25, "Injecting stealth VM & native guard runtime...");
        RuntimeHandles rt = RuntimeInjector.Inject(module, includeBootstrap: false);

        if (options.EnableMethodVirtualization)
        {
            Report(0.38, "Compiling eligible IL methods to randomized Polymorphic VM bytecode...");
            var vmRes = MethodVirtualizerPass.Execute(module, rt, options);
            report.VirtualizedMethods = vmRes.VirtualizedCount;
            report.SkippedVmMethods = vmRes.SkippedCount;
        }
        else
        {
            RuntimeInjector.PatchReturnString(rt.CfgGetVmResource, "");
        }

        if (options.EnableControlFlowObfuscation)
        {
            Report(0.52, "Flattening control flow & injecting opaque predicates...");
            report.FlattenedMethods = ControlFlowPass.Execute(module, rt);
        }

        if (options.EnableConstantMutation)
        {
            Report(0.62, "Mutating numeric constants...");
            report.MutatedConstants = ConstantMutationPass.Execute(module, rt);
        }

        if (options.EnableStringEncryption)
        {
            Report(0.70, "Encrypting string literals with ChaCha20...");
            report.EncryptedStrings = StringEncryptionPass.Execute(module, rt, options);
        }
        else
        {
            RuntimeInjector.PatchReturnString(rt.CfgGetStringResource, "");
        }

        if (options.EnableSymbolRenaming)
        {
            Report(0.76, "Renaming symbols (WPF/BAML-safe)...");
            var renRes = RenamingPass.Execute(module, rt);
            report.RenamedTypes = renRes.Types;
            report.RenamedMethods = renRes.Methods;
            report.RenamedFields = renRes.Fields;
        }

        Report(0.80, "Injecting <Module>::.cctor Anti-Debug & Native x64 PIC Guard...");
        AntiTamperPass.Execute(module, rt, options);

        Report(isSingleFileEntry ? 0.82 : 0.90, "Rebuilding .NET PE image...");
        using var outMs = new MemoryStream();
        var builder = new ManagedPEImageBuilder();
        var peImage = builder.CreateImage(module).ConstructedImage
            ?? throw new InvalidOperationException("Failed to build protected .NET PE image.");
        new ManagedPEFileBuilder().CreateFile(peImage).Write(outMs);
        return outMs.ToArray();
    }
}
