namespace VMProtector.Core;

public enum BinaryKind
{
    Unknown,
    NativePe64,
    DotNetAssembly,
    DotNetSingleFileBundle
}

public enum ProtectionPreset
{
    ToprakExternalMaximum,
    BalancedSafe,
    MaximumStealth,
    NativePe64
}

public sealed class ProtectionOptions
{
    public bool EnableMethodVirtualization { get; set; } = true;
    public bool EnableStringEncryption { get; set; } = true;
    public bool EnableControlFlowObfuscation { get; set; } = true;
    public bool EnableConstantMutation { get; set; } = true;
    public bool EnableSymbolRenaming { get; set; } = true;
    public bool EnableAntiDebug { get; set; } = true;
    public bool EnableToolProcessScan { get; set; } = false;
    public bool EnableAntiIldasmAndStrip { get; set; } = true;
    public bool EnableSingleFileStage2Loader { get; set; } = true;

    /// <summary>
    /// Optional namespace/type substrings prioritized or scoped for VM virtualization.
    /// Empty or "*" virtualizes all eligible methods up to MaxVirtualizedMethods.
    /// </summary>
    public List<string> PriorityScopeFilters { get; set; } = new();

    public int MaxVirtualizedMethods { get; set; } = 1200;

    public static ProtectionOptions FromPreset(ProtectionPreset preset)
    {
        return preset switch
        {
            ProtectionPreset.ToprakExternalMaximum => new ProtectionOptions
            {
                EnableMethodVirtualization = true,
                EnableStringEncryption = true,
                EnableControlFlowObfuscation = true,
                EnableConstantMutation = true,
                EnableSymbolRenaming = true,
                EnableAntiDebug = true,
                EnableToolProcessScan = false,
                EnableAntiIldasmAndStrip = true,
                EnableSingleFileStage2Loader = true,
                MaxVirtualizedMethods = 1500
            },
            ProtectionPreset.BalancedSafe => new ProtectionOptions
            {
                EnableMethodVirtualization = true,
                EnableStringEncryption = true,
                EnableControlFlowObfuscation = true,
                EnableConstantMutation = false,
                EnableSymbolRenaming = false,
                EnableAntiDebug = true,
                EnableToolProcessScan = false,
                EnableAntiIldasmAndStrip = true,
                EnableSingleFileStage2Loader = false,
                MaxVirtualizedMethods = 500
            },
            ProtectionPreset.MaximumStealth => new ProtectionOptions
            {
                EnableMethodVirtualization = true,
                EnableStringEncryption = true,
                EnableControlFlowObfuscation = true,
                EnableConstantMutation = true,
                EnableSymbolRenaming = true,
                EnableAntiDebug = true,
                EnableToolProcessScan = true,
                EnableAntiIldasmAndStrip = true,
                EnableSingleFileStage2Loader = true,
                MaxVirtualizedMethods = 3000
            },
            ProtectionPreset.NativePe64 => new ProtectionOptions
            {
                EnableAntiDebug = true
            },
            _ => new ProtectionOptions()
        };
    }
}

public sealed class SectionMetric
{
    public string Name { get; set; } = "";
    public uint RawSize { get; set; }
    public uint VirtualSize { get; set; }
    public double Entropy { get; set; }
}

public sealed class BinaryInfo
{
    public string FilePath { get; set; } = "";
    public BinaryKind Kind { get; set; }
    public string Architecture { get; set; } = "Unknown";
    public string Subsystem { get; set; } = "Unknown";
    public string TargetFramework { get; set; } = "";
    public bool IsWpf { get; set; }
    public long FileSize { get; set; }
    public double ShannonEntropy { get; set; }
    public string EntryAssemblyName { get; set; } = "";
    public int TotalTypes { get; set; }
    public int TotalMethods { get; set; }
    public int EligibleVmMethods { get; set; }
    public int BundleFileCount { get; set; }
    public List<SectionMetric> Sections { get; set; } = new();
}

public sealed class ProtectionReport
{
    public bool Success { get; set; }
    public string InputPath { get; set; } = "";
    public string OutputPath { get; set; } = "";
    public BinaryKind DetectedKind { get; set; }
    public long InputSize { get; set; }
    public long OutputSize { get; set; }
    public double InputEntropy { get; set; }
    public double OutputEntropy { get; set; }
    public int VirtualizedMethods { get; set; }
    public int SkippedVmMethods { get; set; }
    public int FlattenedMethods { get; set; }
    public int EncryptedStrings { get; set; }
    public int MutatedConstants { get; set; }
    public int RenamedTypes { get; set; }
    public int RenamedMethods { get; set; }
    public int RenamedFields { get; set; }
    public bool Stage2InMemoryBundleApplied { get; set; }
    public bool NativePe64Protected { get; set; }
    public TimeSpan Elapsed { get; set; }
    public string ErrorMessage { get; set; } = "";
}
