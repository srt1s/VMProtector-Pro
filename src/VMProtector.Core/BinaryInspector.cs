using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Bundles;
using AsmResolver.IO;
using AsmResolver.PE;
using AsmResolver.PE.File;

namespace VMProtector.Core;

public static class BinaryInspector
{
    public static BinaryInfo Inspect(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("File not found.", filePath);
        }

        byte[] raw = File.ReadAllBytes(filePath);
        var info = new BinaryInfo
        {
            FilePath = filePath,
            FileSize = raw.Length,
            ShannonEntropy = CryptoUtils.CalculateShannonEntropy(raw)
        };

        var peFile = PEFile.FromBytes(raw);
        info.Architecture = peFile.FileHeader.Machine.ToString();
        info.Subsystem = peFile.OptionalHeader.SubSystem.ToString();

        foreach (PESection sec in peFile.Sections)
        {
            byte[] secData = sec.WriteIntoArray();
            info.Sections.Add(new SectionMetric
            {
                Name = sec.Name,
                RawSize = sec.GetPhysicalSize(),
                VirtualSize = sec.GetVirtualSize(),
                Entropy = CryptoUtils.CalculateShannonEntropy(secData)
            });
        }

        var dataSource = new ByteArrayDataSource(raw);
        BundleManifest? manifest = null;
        try
        {
            if (BundleManifest.IsBundledAssembly(dataSource))
            {
                manifest = BundleManifest.FromDataSource(dataSource);
            }
        }
        catch
        {
            manifest = null;
        }

        if (manifest != null)
        {
            info.Kind = BinaryKind.DotNetSingleFileBundle;
            info.BundleFileCount = manifest.Files.Count;
            if (manifest.TryGetTargetRuntime(out DotNetRuntimeInfo rtInfo))
            {
                info.TargetFramework = rtInfo.ToString();
            }

            BundleFile? entryBundleFile = FindEntryAssemblyBundleFile(manifest);
            if (entryBundleFile != null)
            {
                byte[] entryBytes = entryBundleFile.GetData();
                var mod = ModuleDefinition.FromBytes(entryBytes);
                PopulateDotNetMetrics(mod, info);
            }
        }
        else
        {
            PEImage peImage = PEImage.FromFile(peFile);
            if (peImage.DotNetDirectory != null)
            {
                info.Kind = BinaryKind.DotNetAssembly;
                var mod = ModuleDefinition.FromImage(peImage);
                PopulateDotNetMetrics(mod, info);
            }
            else if (peFile.FileHeader.Machine == MachineType.Amd64)
            {
                info.Kind = BinaryKind.NativePe64;
            }
        }

        return info;
    }

    internal static BundleFile? FindEntryAssemblyBundleFile(BundleManifest manifest)
    {
        // Primary detection: look for runtimeconfig.json stem
        string? stem = null;
        foreach (BundleFile f in manifest.Files)
        {
            if (f.RelativePath.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase))
            {
                stem = f.RelativePath[..^".runtimeconfig.json".Length] + ".dll";
                break;
            }
        }

        if (stem != null)
        {
            BundleFile? match = manifest.Files.FirstOrDefault(
                f => string.Equals(f.RelativePath, stem, StringComparison.OrdinalIgnoreCase));
            if (match != null) return match;
        }

        // Fallback: find the assembly file with a managed EntryPoint
        foreach (BundleFile f in manifest.Files)
        {
            if (f.Type == BundleFileType.Assembly && f.RelativePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var mod = ModuleDefinition.FromBytes(f.GetData());
                    if (mod.ManagedEntryPointMethod != null) return f;
                }
                catch { }
            }
        }

        return null;
    }

    private static void PopulateDotNetMetrics(ModuleDefinition mod, BinaryInfo info)
    {
        info.EntryAssemblyName = mod.Assembly?.Name ?? mod.Name ?? "";
        if (string.IsNullOrEmpty(info.TargetFramework) && !string.IsNullOrEmpty(mod.RuntimeVersion))
        {
            info.TargetFramework = mod.RuntimeVersion;
        }

        info.IsWpf = mod.AssemblyReferences.Any(r =>
            string.Equals(r.Name, "PresentationFramework", StringComparison.OrdinalIgnoreCase));

        int typeCount = 0;
        int methodCount = 0;
        int vmEligible = 0;

        foreach (TypeDefinition t in mod.GetAllTypes())
        {
            if (t.IsModuleType) continue;
            typeCount++;
            foreach (MethodDefinition m in t.Methods)
            {
                methodCount++;
                if (VmEligibility.IsEligible(m, out _)) vmEligible++;
            }
        }

        info.TotalTypes = typeCount;
        info.TotalMethods = methodCount;
        info.EligibleVmMethods = vmEligible;
    }
}
