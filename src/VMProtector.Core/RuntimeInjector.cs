using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Cloning;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace VMProtector.Core;

internal sealed class RuntimeHandles
{
    public required HashSet<TypeDefinition> RuntimeTypes { get; init; }
    public required MethodDefinition StringVaultGet { get; init; }
    public required MethodDefinition VmEngineRun { get; init; }
    public required MethodDefinition SecurityGuardInit { get; init; }
    public required MethodDefinition TokenTableInit { get; init; }
    public required FieldDefinition TokenTypesField { get; init; }
    public required FieldDefinition TokenMethodsField { get; init; }
    public required FieldDefinition TokenFieldsField { get; init; }

    public required MethodDefinition CfgGetStringResource { get; init; }
    public required MethodDefinition CfgGetVmResource { get; init; }
    public required MethodDefinition CfgGetBootResource { get; init; }
    public required MethodDefinition CfgGetStringKey { get; init; }
    public required MethodDefinition CfgGetStringNonce { get; init; }
    public required MethodDefinition CfgGetVmKey { get; init; }
    public required MethodDefinition CfgGetVmNonce { get; init; }
    public required MethodDefinition CfgGetOpcodeMap { get; init; }
    public required MethodDefinition CfgGetBootKey { get; init; }
    public required MethodDefinition CfgGetBootNonce { get; init; }
    public required MethodDefinition CfgGetBootCrc { get; init; }
    public required MethodDefinition CfgGetSecurityFlags { get; init; }
    public MethodDefinition? MemoryBootstrapLaunch { get; init; }
}

internal static class RuntimeInjector
{
    public static RuntimeHandles Inject(ModuleDefinition targetModule, bool includeBootstrap = false)
    {
        byte[] rtBytes = EmbeddedAssets.LoadRuntimeAssemblyBytes();
        ModuleDefinition rtModule = ModuleDefinition.FromBytes(rtBytes);

        var cloner = new MemberCloner(targetModule);
        var sourceTypes = new List<TypeDefinition>();
        string[] targetNames = includeBootstrap
            ? new[] { "CryptoCore", "RuntimeConfig", "NativePicFn", "SecurityGuard", "MemoryBootstrap" }
            : new[] { "CryptoCore", "RuntimeConfig", "NativePicFn", "SecurityGuard", "StringVault", "TokenTable", "VmOp", "VmEngine" };

        foreach (TypeDefinition t in rtModule.TopLevelTypes)
        {
            string tName = t.Name?.ToString() ?? "";
            if ((t.Namespace == "VMProtector.Runtime" && targetNames.Contains(tName)) ||
                tName.StartsWith("<PrivateImplementationDetails>", StringComparison.Ordinal))
            {
                sourceTypes.Add(t);
            }
        }

        cloner.Include(sourceTypes);
        MemberCloneResult cloneRes = cloner.Clone();

        var injectedTypes = new HashSet<TypeDefinition>();
        var typeByOrigName = new Dictionary<string, TypeDefinition>();

        string stealthNs = CryptoUtils.RandomIdentifier(12);
        foreach (TypeDefinition cloned in cloneRes.ClonedTopLevelTypes)
        {
            string origName = cloned.Name?.ToString() ?? "";
            if (origName.StartsWith("<PrivateImplementationDetails>", StringComparison.Ordinal))
            {
                cloned.Name = CryptoUtils.RandomIdentifier(12);
                targetModule.TopLevelTypes.Add(cloned);
                AddWithNested(cloned, injectedTypes);
                continue;
            }
            typeByOrigName[origName] = cloned;
            cloned.Namespace = stealthNs;
            cloned.Name = CryptoUtils.RandomIdentifier(10);
            targetModule.TopLevelTypes.Add(cloned);
            AddWithNested(cloned, injectedTypes);
        }

        // Rename runtime fields/methods cleanly to prevent obvious static pattern matching
        MethodDefinition FindMethod(string typeName, string methodName, int? paramCount = null)
        {
            TypeDefinition td = typeByOrigName[typeName];
            return td.Methods.First(m =>
                m.Name == methodName && (paramCount == null || m.Parameters.Count == paramCount.Value));
        }

        FieldDefinition FindField(string typeName, string fieldName)
        {
            TypeDefinition td = typeByOrigName[typeName];
            return td.Fields.First(f => f.Name == fieldName);
        }

        TypeDefinition cfg = typeByOrigName["RuntimeConfig"];
        var handles = new RuntimeHandles
        {
            RuntimeTypes = injectedTypes,
            SecurityGuardInit = FindMethod("SecurityGuard", "Initialize", 1),
            StringVaultGet = includeBootstrap ? FindMethod("RuntimeConfig", "GetStringResource") : FindMethod("StringVault", "Get", 2),
            VmEngineRun = includeBootstrap ? FindMethod("RuntimeConfig", "GetVmResource") : FindMethod("VmEngine", "Run", 3),
            TokenTableInit = includeBootstrap ? FindMethod("RuntimeConfig", "GetVmResource") : FindMethod("TokenTable", "InitTokens", 0),
            TokenTypesField = includeBootstrap ? cfg.Fields.FirstOrDefault() ?? new FieldDefinition("d", FieldAttributes.Private | FieldAttributes.Static, targetModule.CorLibTypeFactory.Int32) : FindField("TokenTable", "Types"),
            TokenMethodsField = includeBootstrap ? cfg.Fields.FirstOrDefault() ?? new FieldDefinition("d2", FieldAttributes.Private | FieldAttributes.Static, targetModule.CorLibTypeFactory.Int32) : FindField("TokenTable", "Methods"),
            TokenFieldsField = includeBootstrap ? cfg.Fields.FirstOrDefault() ?? new FieldDefinition("d3", FieldAttributes.Private | FieldAttributes.Static, targetModule.CorLibTypeFactory.Int32) : FindField("TokenTable", "Fields"),
            CfgGetStringResource = FindMethod("RuntimeConfig", "GetStringResource"),
            CfgGetVmResource = FindMethod("RuntimeConfig", "GetVmResource"),
            CfgGetBootResource = FindMethod("RuntimeConfig", "GetBootResource"),
            CfgGetStringKey = FindMethod("RuntimeConfig", "GetStringKey"),
            CfgGetStringNonce = FindMethod("RuntimeConfig", "GetStringNonce"),
            CfgGetVmKey = FindMethod("RuntimeConfig", "GetVmKey"),
            CfgGetVmNonce = FindMethod("RuntimeConfig", "GetVmNonce"),
            CfgGetOpcodeMap = FindMethod("RuntimeConfig", "GetOpcodeMap"),
            CfgGetBootKey = FindMethod("RuntimeConfig", "GetBootKey"),
            CfgGetBootNonce = FindMethod("RuntimeConfig", "GetBootNonce"),
            CfgGetBootCrc = FindMethod("RuntimeConfig", "GetBootCrc"),
            CfgGetSecurityFlags = FindMethod("RuntimeConfig", "GetSecurityFlags"),
            MemoryBootstrapLaunch = includeBootstrap ? FindMethod("MemoryBootstrap", "Launch", 1) : null
        };

        // Strip any compiler-generated Nullable/Embedded custom attributes from cloned runtime members
        // and ensure zero AssemblyReference leak back to VMProtector.Runtime
        foreach (TypeDefinition rt in injectedTypes)
        {
            StripRuntimeOnlyAttributes(rt);
            if (rt.IsNested) rt.Name = CryptoUtils.RandomIdentifier(9);
            foreach (MethodDefinition m in rt.Methods)
            {
                StripRuntimeOnlyAttributes(m);
                if (!m.IsConstructor && !m.IsSpecialName && !m.IsRuntimeSpecialName && !m.IsPInvokeImpl && !m.IsVirtual &&
                    m.Name != "Invoke" && m.Name != "BeginInvoke" && m.Name != "EndInvoke")
                {
                    m.Name = CryptoUtils.RandomIdentifier(10);
                }
            }
            foreach (FieldDefinition f in rt.Fields)
            {
                StripRuntimeOnlyAttributes(f);
                if (!f.IsSpecialName && !f.IsRuntimeSpecialName)
                {
                    f.Name = CryptoUtils.RandomIdentifier(9);
                }
            }
        }

        for (int i = targetModule.AssemblyReferences.Count - 1; i >= 0; i--)
        {
            if (string.Equals(targetModule.AssemblyReferences[i].Name, "VMProtector.Runtime", StringComparison.OrdinalIgnoreCase))
            {
                targetModule.AssemblyReferences.RemoveAt(i);
            }
        }

        return handles;
    }

    private static void StripRuntimeOnlyAttributes(IHasCustomAttribute target)
    {
        for (int i = target.CustomAttributes.Count - 1; i >= 0; i--)
        {
            string? scopeName = target.CustomAttributes[i].Constructor?.DeclaringType?.Scope?.Name;
            string? typeName = target.CustomAttributes[i].Constructor?.DeclaringType?.Name;
            if (string.Equals(scopeName, "VMProtector.Runtime", StringComparison.OrdinalIgnoreCase) ||
                typeName is "NullableAttribute" or "NullableContextAttribute" or "EmbeddedAttribute" or "RefSafetyRulesAttribute")
            {
                target.CustomAttributes.RemoveAt(i);
            }
        }
    }

    private static void AddWithNested(TypeDefinition t, HashSet<TypeDefinition> set)
    {
        set.Add(t);
        foreach (TypeDefinition n in t.NestedTypes)
        {
            AddWithNested(n, set);
        }
    }

    public static void PatchReturnString(MethodDefinition method, string value)
    {
        var body = new CilMethodBody(method);
        body.Instructions.Add(CilOpCodes.Ldstr, value);
        body.Instructions.Add(CilOpCodes.Ret);
        method.CilMethodBody = body;
    }

    public static void PatchReturnInt32(MethodDefinition method, int value)
    {
        var body = new CilMethodBody(method);
        body.Instructions.Add(CilOpCodes.Ldc_I4, value);
        body.Instructions.Add(CilOpCodes.Ret);
        method.CilMethodBody = body;
    }

    public static void PatchReturnUInt32(MethodDefinition method, uint value)
    {
        var body = new CilMethodBody(method);
        body.Instructions.Add(CilOpCodes.Ldc_I4, unchecked((int)value));
        body.Instructions.Add(CilOpCodes.Ret);
        method.CilMethodBody = body;
    }

    /// <summary>
    /// Compiles a byte[] getter method using polymorphic XOR arithmetic instead of a raw array blob,
    /// hiding keys/opcode tables from static binary scanning.
    /// </summary>
    public static void PatchReturnObfuscatedByteArray(MethodDefinition method, byte[] data)
    {
        var cor = method.DeclaringType!.Module!.CorLibTypeFactory;
        var body = new CilMethodBody(method);
        var arrLocal = new CilLocalVariable(cor.Byte.MakeSzArrayType());
        body.LocalVariables.Add(arrLocal);

        body.Instructions.Add(CilOpCodes.Ldc_I4, data.Length);
        body.Instructions.Add(CilOpCodes.Newarr, cor.Byte.ToTypeDefOrRef());
        body.Instructions.Add(CilOpCodes.Stloc, arrLocal);

        // Emit elements in a shuffled order so byte patterns are scattered in IL
        int[] indices = Enumerable.Range(0, data.Length).ToArray();
        Random.Shared.Shuffle(indices);

        foreach (int idx in indices)
        {
            int mask = CryptoUtils.RandomInt() & 0xFF;
            int maskedVal = data[idx] ^ mask;

            body.Instructions.Add(CilOpCodes.Ldloc, arrLocal);
            body.Instructions.Add(CilOpCodes.Ldc_I4, idx);
            body.Instructions.Add(CilOpCodes.Ldc_I4, maskedVal);
            body.Instructions.Add(CilOpCodes.Ldc_I4, mask);
            body.Instructions.Add(CilOpCodes.Xor);
            body.Instructions.Add(CilOpCodes.Conv_U1);
            body.Instructions.Add(CilOpCodes.Stelem_I1);
        }

        body.Instructions.Add(CilOpCodes.Ldloc, arrLocal);
        body.Instructions.Add(CilOpCodes.Ret);
        method.CilMethodBody = body;
    }
}
