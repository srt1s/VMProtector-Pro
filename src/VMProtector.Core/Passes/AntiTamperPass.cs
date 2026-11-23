using System.Diagnostics;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace VMProtector.Core.Passes;

internal static class AntiTamperPass
{
    public static void Execute(ModuleDefinition module, RuntimeHandles rt, ProtectionOptions options)
    {
        int secFlags = 0;
        if (options.EnableAntiDebug) secFlags |= 1;
        if (options.EnableToolProcessScan) secFlags |= 4;

        RuntimeInjector.PatchReturnInt32(rt.CfgGetSecurityFlags, secFlags);

        if (options.EnableAntiDebug)
        {
            MethodDefinition cctor = module.GetOrCreateModuleConstructor();
            CilMethodBody body = cctor.CilMethodBody ?? new CilMethodBody(cctor);
            cctor.CilMethodBody = body;

            if (body.Instructions.Count == 0)
            {
                body.Instructions.Add(CilOpCodes.Ret);
            }

            body.Instructions.Insert(0, new CilInstruction(CilOpCodes.Ldc_I4, secFlags));
            body.Instructions.Insert(1, new CilInstruction(CilOpCodes.Call, rt.SecurityGuardInit));
            body.Instructions.CalculateOffsets();
        }

        if (options.EnableAntiIldasmAndStrip)
        {
            // Add [assembly: SuppressIldasmAttribute]
#pragma warning disable SYSLIB0025 // SuppressIldasmAttribute still respected by ILSpy/ildasm tools
            if (module.Assembly != null)
            {
                var importer = module.DefaultImporter;
                var attrCtor = typeof(System.Runtime.CompilerServices.SuppressIldasmAttribute).GetConstructor(Type.EmptyTypes);
                if (attrCtor != null)
                {
                    IMethodDescriptor importedCtor = importer.ImportMethod(attrCtor);
                    bool already = module.Assembly.CustomAttributes.Any(ca =>
                        ca.Constructor?.DeclaringType?.Name == nameof(System.Runtime.CompilerServices.SuppressIldasmAttribute));
                    if (!already)
                    {
                        module.Assembly.CustomAttributes.Add(new CustomAttribute((ICustomAttributeType)importedCtor));
                    }
                }
            }
#pragma warning restore SYSLIB0025

            // Strip PDB / Debug directory info
            module.DebugData.Clear();
        }
    }
}
