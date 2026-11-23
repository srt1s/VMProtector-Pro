using System.IO.Compression;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.Builder;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace VMProtector.Core.Passes;

internal static class SingleFileStage2Builder
{
    public static byte[] BuildStage2LoaderAssembly(
        byte[] originalCleanModuleBytes,
        byte[] protectedPayloadDllBytes,
        ProtectionOptions options)
    {
        // Start from a clean clone of the original module shell so CorLib, TargetRuntime, Win32 .rsrc,
        // and AssemblyMetadata (e.g. ToprakEmbeddedLicense) are 100% genuine and intact.
        ModuleDefinition stubMod = ModuleDefinition.FromBytes(originalCleanModuleBytes);
        stubMod.ManagedEntryPointMethod = null;
        stubMod.DebugData.Clear();

        for (int i = stubMod.TopLevelTypes.Count - 1; i >= 0; i--)
        {
            if (!stubMod.TopLevelTypes[i].IsModuleType)
            {
                stubMod.TopLevelTypes.RemoveAt(i);
            }
        }
        stubMod.Resources.Clear();

        // Wipe any leftover user code inside <Module>::.cctor
        TypeDefinition modType = stubMod.GetOrCreateModuleType();
        modType.Methods.Clear();
        modType.Fields.Clear();

        // Inject minimal runtime (CryptoCore, RuntimeConfig, SecurityGuard, MemoryBootstrap)
        RuntimeHandles rt = RuntimeInjector.Inject(stubMod, includeBootstrap: true);

        // Compress + ChaCha20 encrypt the already-hardened payload DLL
        byte[] compressed;
        using (var cms = new MemoryStream())
        {
            using (var ds = new DeflateStream(cms, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                ds.Write(protectedPayloadDllBytes, 0, protectedPayloadDllBytes.Length);
            }
            compressed = cms.ToArray();
        }

        uint crc = CryptoUtils.Crc32(compressed);
        byte[] key = CryptoUtils.RandomBytes(32);
        byte[] nonce = CryptoUtils.RandomBytes(12);
        byte[] encrypted = CryptoUtils.ChaCha20Xor(key, nonce, 1u, compressed);

        string resName = "." + CryptoUtils.RandomIdentifier(12);
        stubMod.Resources.Add(new ManifestResource(resName, ManifestResourceAttributes.Private, new DataSegment(encrypted)));

        int secFlags = 0;
        if (options.EnableAntiDebug) secFlags |= 1;
        if (options.EnableToolProcessScan) secFlags |= 4;

        RuntimeInjector.PatchReturnString(rt.CfgGetBootResource, resName);
        RuntimeInjector.PatchReturnObfuscatedByteArray(rt.CfgGetBootKey, key);
        RuntimeInjector.PatchReturnObfuscatedByteArray(rt.CfgGetBootNonce, nonce);
        RuntimeInjector.PatchReturnUInt32(rt.CfgGetBootCrc, crc);
        RuntimeInjector.PatchReturnInt32(rt.CfgGetSecurityFlags, secFlags);

        // Create EntryPoint class with [STAThread] static int Main(string[] args)
        var cor = stubMod.CorLibTypeFactory;
        var entryType = new TypeDefinition(
            "",
            CryptoUtils.RandomIdentifier(10),
            TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class,
            cor.Object.ToTypeDefOrRef());
        stubMod.TopLevelTypes.Add(entryType);

        var mainSig = MethodSignature.CreateStatic(cor.Int32, cor.String.MakeSzArrayType());
        var mainMethod = new MethodDefinition(
            CryptoUtils.RandomIdentifier(8),
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig,
            mainSig);
        mainMethod.ParameterDefinitions.Add(new ParameterDefinition(1, null, 0));

        // Attach [STAThreadAttribute] required for WPF!
        var staCtor = typeof(STAThreadAttribute).GetConstructor(Type.EmptyTypes);
        if (staCtor != null)
        {
            var importedSta = (ICustomAttributeType)stubMod.DefaultImporter.ImportMethod(staCtor);
            mainMethod.CustomAttributes.Add(new CustomAttribute(importedSta));
        }

        var body = new CilMethodBody(mainMethod);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Call, rt.MemoryBootstrapLaunch!);
        body.Instructions.Add(CilOpCodes.Ret);
        mainMethod.CilMethodBody = body;
        entryType.Methods.Add(mainMethod);
        stubMod.ManagedEntryPointMethod = mainMethod;

        var builder = new ManagedPEImageBuilder();
        var peImage = builder.CreateImage(stubMod).ConstructedImage
            ?? throw new InvalidOperationException("Failed to build Stage-2 PE image.");

        using var outMs = new MemoryStream();
        new ManagedPEFileBuilder().CreateFile(peImage).Write(outMs);
        return outMs.ToArray();
    }
}
