using System.Security.Cryptography;
using System.Text;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace VMProtector.Core.Passes;

internal enum VmOpCode : byte
{
    Nop = 0x00,
    LdcI4 = 0x01,
    LdcI8 = 0x02,
    LdcR4 = 0x03,
    LdcR8 = 0x04,
    LdNull = 0x05,
    LdStr = 0x06,

    LdArg = 0x10,
    StArg = 0x11,
    LdLoc = 0x12,
    StLoc = 0x13,
    Dup = 0x14,
    Pop = 0x15,

    Add = 0x20,
    Sub = 0x21,
    Mul = 0x22,
    Div = 0x23,
    DivUn = 0x24,
    Rem = 0x25,
    RemUn = 0x26,
    Neg = 0x27,
    Not = 0x28,
    And = 0x29,
    Or = 0x2A,
    Xor = 0x2B,
    Shl = 0x2C,
    Shr = 0x2D,
    ShrUn = 0x2E,

    ConvI1 = 0x30,
    ConvU1 = 0x31,
    ConvI2 = 0x32,
    ConvU2 = 0x33,
    ConvI4 = 0x34,
    ConvU4 = 0x35,
    ConvI8 = 0x36,
    ConvU8 = 0x37,
    ConvR4 = 0x38,
    ConvR8 = 0x39,

    Ceq = 0x40,
    Cgt = 0x41,
    CgtUn = 0x42,
    Clt = 0x43,
    CltUn = 0x44,

    Br = 0x50,
    BrTrue = 0x51,
    BrFalse = 0x52,
    Beq = 0x53,
    BneUn = 0x54,
    Bge = 0x55,
    BgeUn = 0x56,
    Bgt = 0x57,
    BgtUn = 0x58,
    Ble = 0x59,
    BleUn = 0x5A,
    Blt = 0x5B,
    BltUn = 0x5C,
    Switch = 0x5D,

    LdFld = 0x60,
    StFld = 0x61,
    LdSFld = 0x62,
    StSFld = 0x63,
    Call = 0x64,
    CallVirt = 0x65,
    NewObj = 0x66,
    CastClass = 0x67,
    IsInst = 0x68,
    Box = 0x69,
    UnboxAny = 0x6A,
    NewArr = 0x6B,
    LdLen = 0x6C,
    LdElem = 0x6D,
    StElem = 0x6E,
    LdToken = 0x6F,

    Throw = 0xFE,
    Ret = 0xFF
}

internal static class MethodVirtualizerPass
{
    public sealed class Result
    {
        public int VirtualizedCount { get; set; }
        public int SkippedCount { get; set; }
    }

    private sealed class TokenCollector
    {
        private readonly Dictionary<ITypeDefOrRef, int> _typeSlots = new(SignatureComparer.Default);
        private readonly Dictionary<IMethodDescriptor, int> _methodSlots = new(SignatureComparer.Default);
        private readonly Dictionary<IFieldDescriptor, int> _fieldSlots = new(SignatureComparer.Default);

        public List<ITypeDefOrRef> Types { get; } = new();
        public List<IMethodDescriptor> Methods { get; } = new();
        public List<IFieldDescriptor> Fields { get; } = new();

        public int GetTypeSlot(ITypeDefOrRef t)
        {
            if (_typeSlots.TryGetValue(t, out int slot)) return slot;
            slot = Types.Count;
            Types.Add(t);
            _typeSlots[t] = slot;
            return slot;
        }

        public int GetMethodSlot(IMethodDescriptor m)
        {
            if (_methodSlots.TryGetValue(m, out int slot)) return slot;
            slot = Methods.Count;
            Methods.Add(m);
            _methodSlots[m] = slot;
            return slot;
        }

        public int GetFieldSlot(IFieldDescriptor f)
        {
            if (_fieldSlots.TryGetValue(f, out int slot)) return slot;
            slot = Fields.Count;
            Fields.Add(f);
            _fieldSlots[f] = slot;
            return slot;
        }
    }

    private sealed class CompiledChunk
    {
        public required MethodDefinition Method { get; init; }
        public int LocalCount { get; init; }
        public int ReturnTypeSlot { get; init; }
        public required byte[] Bytecode { get; init; }
    }

    public static Result Execute(ModuleDefinition module, RuntimeHandles rt, ProtectionOptions options)
    {
        var result = new Result();
        var candidates = new List<(MethodDefinition method, int priority)>();

        foreach (TypeDefinition type in module.GetAllTypes())
        {
            if (rt.RuntimeTypes.Contains(type) || type.IsModuleType) continue;
            string fullName = type.FullName ?? "";

            foreach (MethodDefinition m in type.Methods)
            {
                if (!VmEligibility.IsEligible(m, out _))
                {
                    if (m.HasMethodBody && !m.IsConstructor && !m.IsRuntimeSpecialName) result.SkippedCount++;
                    continue;
                }

                if (m.CilMethodBody!.MaxStack > 96)
                {
                    result.SkippedCount++;
                    continue;
                }

                // Ensure stfld isn't mutating a struct by value
                if (HasStructStfld(m.CilMethodBody))
                {
                    result.SkippedCount++;
                    continue;
                }

                int prio = 0;
                if (options.PriorityScopeFilters.Count > 0)
                {
                    foreach (string filter in options.PriorityScopeFilters)
                    {
                        if (fullName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                            (m.Name?.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false))
                        {
                            prio = 10;
                            break;
                        }
                    }
                }
                else
                {
                    if (fullName.Contains("license", StringComparison.OrdinalIgnoreCase) ||
                        fullName.Contains("security", StringComparison.OrdinalIgnoreCase) ||
                        fullName.Contains("offset", StringComparison.OrdinalIgnoreCase) ||
                        fullName.Contains("aim", StringComparison.OrdinalIgnoreCase) ||
                        fullName.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                        fullName.Contains("hwid", StringComparison.OrdinalIgnoreCase))
                    {
                        prio = 10;
                    }
                }

                candidates.Add((m, prio));
            }
        }

        // Order highest priority + largest methods first up to MaxVirtualizedMethods
        var selected = candidates
            .OrderByDescending(c => c.priority)
            .ThenByDescending(c => c.method.CilMethodBody!.Instructions.Count)
            .Take(options.MaxVirtualizedMethods)
            .Select(c => c.method)
            .ToList();

        // Build per-build randomized opcode permutation
        VmOpCode[] allOps = Enum.GetValues<VmOpCode>();
        byte[] physCodes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        Random.Shared.Shuffle(physCodes);

        var encodeMap = new Dictionary<VmOpCode, byte>(allOps.Length);
        byte[] decodeMap = new byte[256];
        for (int i = 0; i < allOps.Length; i++)
        {
            byte phys = physCodes[i];
            encodeMap[allOps[i]] = phys;
            decodeMap[phys] = (byte)allOps[i];
        }

        var tokenCollector = new TokenCollector();
        var vmStrings = new List<string>();
        var vmStringIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        var chunks = new List<CompiledChunk>();

        foreach (MethodDefinition m in selected)
        {
            if (TryCompileMethod(module, m, encodeMap, tokenCollector, vmStrings, vmStringIndex, out CompiledChunk? chunk) && chunk != null)
            {
                chunks.Add(chunk);
                result.VirtualizedCount++;
            }
            else
            {
                result.SkippedCount++;
            }
        }

        if (chunks.Count == 0)
        {
            RuntimeInjector.PatchReturnString(rt.CfgGetVmResource, "");
            return result;
        }

        // Replace original method bodies with compact VM stubs
        for (int methodId = 0; methodId < chunks.Count; methodId++)
        {
            ReplaceWithVmStub(module, rt, chunks[methodId].Method, methodId);
        }

        // Compile TokenTable.InitTokens() using real OpCodes.Ldtoken so ManagedPEImageBuilder writes valid final tokens!
        BuildTokenInitializer(module, rt, tokenCollector);

        // Serialize VM payload (string pool + compiled chunks) -> ChaCha20 encrypt -> store as resource
        using var plainMs = new MemoryStream();
        using (var bw = new BinaryWriter(plainMs, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write(vmStrings.Count);
            foreach (string s in vmStrings)
            {
                byte[] utf8 = Encoding.UTF8.GetBytes(s);
                bw.Write(utf8.Length);
                bw.Write(utf8);
            }

            bw.Write(chunks.Count);
            foreach (CompiledChunk ch in chunks)
            {
                bw.Write(ch.LocalCount);
                bw.Write(ch.ReturnTypeSlot);
                bw.Write(ch.Bytecode.Length);
                bw.Write(ch.Bytecode);
            }
        }

        byte[] vmKey = CryptoUtils.RandomBytes(32);
        byte[] vmNonce = CryptoUtils.RandomBytes(12);
        byte[] enc = CryptoUtils.ChaCha20Xor(vmKey, vmNonce, 1u, plainMs.ToArray());

        string resName = "." + CryptoUtils.RandomIdentifier(12);
        module.Resources.Add(new ManifestResource(resName, ManifestResourceAttributes.Private, new DataSegment(enc)));

        RuntimeInjector.PatchReturnString(rt.CfgGetVmResource, resName);
        RuntimeInjector.PatchReturnObfuscatedByteArray(rt.CfgGetVmKey, vmKey);
        RuntimeInjector.PatchReturnObfuscatedByteArray(rt.CfgGetVmNonce, vmNonce);
        RuntimeInjector.PatchReturnObfuscatedByteArray(rt.CfgGetOpcodeMap, decodeMap);

        return result;
    }

    private static bool HasStructStfld(CilMethodBody body)
    {
        foreach (CilInstruction insn in body.Instructions)
        {
            if (insn.OpCode.Code == CilCode.Stfld && insn.Operand is IFieldDescriptor fd)
            {
                if (fd.DeclaringType?.IsValueType == true) return true;
                if (fd.DeclaringType?.Resolve()?.IsValueType == true) return true;
            }
        }
        return false;
    }

    private static bool TryCompileMethod(
        ModuleDefinition module,
        MethodDefinition method,
        Dictionary<VmOpCode, byte> encMap,
        TokenCollector tokens,
        List<string> vmStrings,
        Dictionary<string, int> vmStringIdx,
        out CompiledChunk? chunk)
    {
        chunk = null;
        CilMethodBody body = method.CilMethodBody!;
        body.Instructions.ExpandMacros();

        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        var cilToVmOffset = new Dictionary<CilInstruction, int>();
        var branchFixups = new List<(int fixupPos, CilInstruction target)>();
        var importer = module.DefaultImporter;

        foreach (CilInstruction insn in body.Instructions)
        {
            cilToVmOffset[insn] = (int)ms.Position;
            CilCode c = insn.OpCode.Code;

            switch (c)
            {
                case CilCode.Nop:
                    bw.Write(encMap[VmOpCode.Nop]);
                    break;

                case CilCode.Ldc_I4:
                    bw.Write(encMap[VmOpCode.LdcI4]);
                    bw.Write((int)insn.Operand!);
                    break;
                case CilCode.Ldc_I8:
                    bw.Write(encMap[VmOpCode.LdcI8]);
                    bw.Write((long)insn.Operand!);
                    break;
                case CilCode.Ldc_R4:
                    bw.Write(encMap[VmOpCode.LdcR4]);
                    bw.Write((float)insn.Operand!);
                    break;
                case CilCode.Ldc_R8:
                    bw.Write(encMap[VmOpCode.LdcR8]);
                    bw.Write((double)insn.Operand!);
                    break;
                case CilCode.Ldnull:
                    bw.Write(encMap[VmOpCode.LdNull]);
                    break;
                case CilCode.Ldstr:
                {
                    string s = (string)insn.Operand!;
                    if (!vmStringIdx.TryGetValue(s, out int sId))
                    {
                        sId = vmStrings.Count;
                        vmStrings.Add(s);
                        vmStringIdx[s] = sId;
                    }
                    bw.Write(encMap[VmOpCode.LdStr]);
                    bw.Write(sId);
                    break;
                }

                case CilCode.Ldarg:
                {
                    var p = insn.GetParameter(method.Parameters);
                    ushort realIdx = checked((ushort)p.MethodSignatureIndex);
                    bw.Write(encMap[VmOpCode.LdArg]);
                    bw.Write(realIdx);
                    break;
                }
                case CilCode.Starg:
                {
                    var p = insn.GetParameter(method.Parameters);
                    ushort realIdx = checked((ushort)p.MethodSignatureIndex);
                    bw.Write(encMap[VmOpCode.StArg]);
                    bw.Write(realIdx);
                    break;
                }
                case CilCode.Ldloc:
                {
                    var loc = insn.GetLocalVariable(body.LocalVariables);
                    ushort locIdx = checked((ushort)loc.Index);
                    bw.Write(encMap[VmOpCode.LdLoc]);
                    bw.Write(locIdx);
                    break;
                }
                case CilCode.Stloc:
                {
                    var loc = insn.GetLocalVariable(body.LocalVariables);
                    ushort locIdx = checked((ushort)loc.Index);
                    bw.Write(encMap[VmOpCode.StLoc]);
                    bw.Write(locIdx);
                    break;
                }
                case CilCode.Dup: bw.Write(encMap[VmOpCode.Dup]); break;
                case CilCode.Pop: bw.Write(encMap[VmOpCode.Pop]); break;

                case CilCode.Add or CilCode.Add_Ovf or CilCode.Add_Ovf_Un: bw.Write(encMap[VmOpCode.Add]); break;
                case CilCode.Sub or CilCode.Sub_Ovf or CilCode.Sub_Ovf_Un: bw.Write(encMap[VmOpCode.Sub]); break;
                case CilCode.Mul or CilCode.Mul_Ovf or CilCode.Mul_Ovf_Un: bw.Write(encMap[VmOpCode.Mul]); break;
                case CilCode.Div: bw.Write(encMap[VmOpCode.Div]); break;
                case CilCode.Div_Un: bw.Write(encMap[VmOpCode.DivUn]); break;
                case CilCode.Rem: bw.Write(encMap[VmOpCode.Rem]); break;
                case CilCode.Rem_Un: bw.Write(encMap[VmOpCode.RemUn]); break;
                case CilCode.Neg: bw.Write(encMap[VmOpCode.Neg]); break;
                case CilCode.Not: bw.Write(encMap[VmOpCode.Not]); break;
                case CilCode.And: bw.Write(encMap[VmOpCode.And]); break;
                case CilCode.Or: bw.Write(encMap[VmOpCode.Or]); break;
                case CilCode.Xor: bw.Write(encMap[VmOpCode.Xor]); break;
                case CilCode.Shl: bw.Write(encMap[VmOpCode.Shl]); break;
                case CilCode.Shr: bw.Write(encMap[VmOpCode.Shr]); break;
                case CilCode.Shr_Un: bw.Write(encMap[VmOpCode.ShrUn]); break;

                case CilCode.Conv_I1: bw.Write(encMap[VmOpCode.ConvI1]); break;
                case CilCode.Conv_U1: bw.Write(encMap[VmOpCode.ConvU1]); break;
                case CilCode.Conv_I2: bw.Write(encMap[VmOpCode.ConvI2]); break;
                case CilCode.Conv_U2: bw.Write(encMap[VmOpCode.ConvU2]); break;
                case CilCode.Conv_I4: bw.Write(encMap[VmOpCode.ConvI4]); break;
                case CilCode.Conv_U4: bw.Write(encMap[VmOpCode.ConvU4]); break;
                case CilCode.Conv_I8: bw.Write(encMap[VmOpCode.ConvI8]); break;
                case CilCode.Conv_U8: bw.Write(encMap[VmOpCode.ConvU8]); break;
                case CilCode.Conv_R4: bw.Write(encMap[VmOpCode.ConvR4]); break;
                case CilCode.Conv_R8 or CilCode.Conv_R_Un: bw.Write(encMap[VmOpCode.ConvR8]); break;

                case CilCode.Ceq: bw.Write(encMap[VmOpCode.Ceq]); break;
                case CilCode.Cgt: bw.Write(encMap[VmOpCode.Cgt]); break;
                case CilCode.Cgt_Un: bw.Write(encMap[VmOpCode.CgtUn]); break;
                case CilCode.Clt: bw.Write(encMap[VmOpCode.Clt]); break;
                case CilCode.Clt_Un: bw.Write(encMap[VmOpCode.CltUn]); break;

                case CilCode.Br:
                case CilCode.Brtrue:
                case CilCode.Brfalse:
                case CilCode.Beq:
                case CilCode.Bne_Un:
                case CilCode.Bge:
                case CilCode.Bge_Un:
                case CilCode.Bgt:
                case CilCode.Bgt_Un:
                case CilCode.Ble:
                case CilCode.Ble_Un:
                case CilCode.Blt:
                case CilCode.Blt_Un:
                {
                    VmOpCode vop = c switch
                    {
                        CilCode.Br => VmOpCode.Br,
                        CilCode.Brtrue => VmOpCode.BrTrue,
                        CilCode.Brfalse => VmOpCode.BrFalse,
                        CilCode.Beq => VmOpCode.Beq,
                        CilCode.Bne_Un => VmOpCode.BneUn,
                        CilCode.Bge => VmOpCode.Bge,
                        CilCode.Bge_Un => VmOpCode.BgeUn,
                        CilCode.Bgt => VmOpCode.Bgt,
                        CilCode.Bgt_Un => VmOpCode.BgtUn,
                        CilCode.Ble => VmOpCode.Ble,
                        CilCode.Ble_Un => VmOpCode.BleUn,
                        CilCode.Blt => VmOpCode.Blt,
                        _ => VmOpCode.BltUn
                    };
                    bw.Write(encMap[vop]);
                    var label = (ICilLabel)insn.Operand!;
                    CilInstruction targetInsn = ((CilInstructionLabel)label).Instruction!;
                    branchFixups.Add(((int)ms.Position, targetInsn));
                    bw.Write(0);
                    break;
                }

                case CilCode.Switch:
                {
                    var labels = (IList<ICilLabel>)insn.Operand!;
                    bw.Write(encMap[VmOpCode.Switch]);
                    bw.Write(labels.Count);
                    foreach (ICilLabel lbl in labels)
                    {
                        CilInstruction targetInsn = ((CilInstructionLabel)lbl).Instruction!;
                        branchFixups.Add(((int)ms.Position, targetInsn));
                        bw.Write(0);
                    }
                    break;
                }

                case CilCode.Ldfld:
                    bw.Write(encMap[VmOpCode.LdFld]);
                    bw.Write(tokens.GetFieldSlot((IFieldDescriptor)insn.Operand!));
                    break;
                case CilCode.Stfld:
                    bw.Write(encMap[VmOpCode.StFld]);
                    bw.Write(tokens.GetFieldSlot((IFieldDescriptor)insn.Operand!));
                    break;
                case CilCode.Ldsfld:
                    bw.Write(encMap[VmOpCode.LdSFld]);
                    bw.Write(tokens.GetFieldSlot((IFieldDescriptor)insn.Operand!));
                    break;
                case CilCode.Stsfld:
                    bw.Write(encMap[VmOpCode.StSFld]);
                    bw.Write(tokens.GetFieldSlot((IFieldDescriptor)insn.Operand!));
                    break;

                case CilCode.Call:
                    bw.Write(encMap[VmOpCode.Call]);
                    bw.Write(tokens.GetMethodSlot((IMethodDescriptor)insn.Operand!));
                    break;
                case CilCode.Callvirt:
                    bw.Write(encMap[VmOpCode.CallVirt]);
                    bw.Write(tokens.GetMethodSlot((IMethodDescriptor)insn.Operand!));
                    break;
                case CilCode.Newobj:
                    bw.Write(encMap[VmOpCode.NewObj]);
                    bw.Write(tokens.GetMethodSlot((IMethodDescriptor)insn.Operand!));
                    break;

                case CilCode.Castclass:
                    bw.Write(encMap[VmOpCode.CastClass]);
                    bw.Write(tokens.GetTypeSlot((ITypeDefOrRef)insn.Operand!));
                    break;
                case CilCode.Isinst:
                    bw.Write(encMap[VmOpCode.IsInst]);
                    bw.Write(tokens.GetTypeSlot((ITypeDefOrRef)insn.Operand!));
                    break;
                case CilCode.Box:
                    bw.Write(encMap[VmOpCode.Box]);
                    bw.Write(tokens.GetTypeSlot((ITypeDefOrRef)insn.Operand!));
                    break;
                case CilCode.Unbox_Any:
                    bw.Write(encMap[VmOpCode.UnboxAny]);
                    bw.Write(tokens.GetTypeSlot((ITypeDefOrRef)insn.Operand!));
                    break;
                case CilCode.Newarr:
                    bw.Write(encMap[VmOpCode.NewArr]);
                    bw.Write(tokens.GetTypeSlot((ITypeDefOrRef)insn.Operand!));
                    break;
                case CilCode.Ldlen:
                    bw.Write(encMap[VmOpCode.LdLen]);
                    break;
                case CilCode.Ldelem_I1 or CilCode.Ldelem_U1 or CilCode.Ldelem_I2 or CilCode.Ldelem_U2
                  or CilCode.Ldelem_I4 or CilCode.Ldelem_U4 or CilCode.Ldelem_I8 or CilCode.Ldelem_R4
                  or CilCode.Ldelem_R8 or CilCode.Ldelem_Ref or CilCode.Ldelem:
                {
                    int slot = insn.Operand is ITypeDefOrRef td ? tokens.GetTypeSlot(td) : -1;
                    bw.Write(encMap[VmOpCode.LdElem]);
                    bw.Write(slot);
                    break;
                }
                case CilCode.Stelem_I1 or CilCode.Stelem_I2 or CilCode.Stelem_I4 or CilCode.Stelem_I8
                  or CilCode.Stelem_R4 or CilCode.Stelem_R8 or CilCode.Stelem_Ref or CilCode.Stelem:
                {
                    int slot = insn.Operand is ITypeDefOrRef td ? tokens.GetTypeSlot(td) : -1;
                    bw.Write(encMap[VmOpCode.StElem]);
                    bw.Write(slot);
                    break;
                }

                case CilCode.Ldtoken:
                {
                    bw.Write(encMap[VmOpCode.LdToken]);
                    if (insn.Operand is ITypeDefOrRef td)
                    {
                        bw.Write((byte)0);
                        bw.Write(tokens.GetTypeSlot(td));
                    }
                    else if (insn.Operand is IFieldDescriptor fd)
                    {
                        bw.Write((byte)1);
                        bw.Write(tokens.GetFieldSlot(fd));
                    }
                    else if (insn.Operand is IMethodDescriptor md)
                    {
                        bw.Write((byte)2);
                        bw.Write(tokens.GetMethodSlot(md));
                    }
                    else return false;
                    break;
                }

                case CilCode.Throw: bw.Write(encMap[VmOpCode.Throw]); break;
                case CilCode.Ret: bw.Write(encMap[VmOpCode.Ret]); break;

                default:
                    return false;
            }
        }

        bw.Flush();
        byte[] bytecode = ms.ToArray();

        foreach (var (fixupPos, targetInsn) in branchFixups)
        {
            if (!cilToVmOffset.TryGetValue(targetInsn, out int vmTarget))
            {
                return false;
            }
            BitConverter.TryWriteBytes(bytecode.AsSpan(fixupPos, 4), vmTarget);
        }

        int retSlot = -1;
        TypeSignature retSig = method.Signature!.ReturnType;
        if (retSig.ElementType != AsmResolver.PE.DotNet.Metadata.Tables.ElementType.Void)
        {
            retSlot = tokens.GetTypeSlot(retSig.ToTypeDefOrRef());
        }

        chunk = new CompiledChunk
        {
            Method = method,
            LocalCount = body.LocalVariables.Count,
            ReturnTypeSlot = retSlot,
            Bytecode = bytecode
        };
        return true;
    }

    private static void ReplaceWithVmStub(ModuleDefinition module, RuntimeHandles rt, MethodDefinition m, int methodId)
    {
        var cor = module.CorLibTypeFactory;
        var sig = m.Signature!;
        int totalArgs = (sig.HasThis ? 1 : 0) + sig.ParameterTypes.Count;

        var body = new CilMethodBody(m);
        int salt = CryptoUtils.RandomInt();
        body.Instructions.Add(CilOpCodes.Ldc_I4, methodId ^ salt);
        body.Instructions.Add(CilOpCodes.Ldc_I4, salt);

        if (totalArgs == 0)
        {
            body.Instructions.Add(CilOpCodes.Ldnull);
        }
        else
        {
            body.Instructions.Add(CilOpCodes.Ldc_I4, totalArgs);
            body.Instructions.Add(CilOpCodes.Newarr, cor.Object.ToTypeDefOrRef());

            for (int i = 0; i < totalArgs; i++)
            {
                body.Instructions.Add(CilOpCodes.Dup);
                body.Instructions.Add(CilOpCodes.Ldc_I4, i);

                AsmResolver.DotNet.Collections.Parameter paramObj = (i == 0 && sig.HasThis)
                    ? m.Parameters.ThisParameter!
                    : m.Parameters[sig.HasThis ? i - 1 : i];
                body.Instructions.Add(CilOpCodes.Ldarg, paramObj);

                if (i == 0 && sig.HasThis)
                {
                    if (m.DeclaringType!.IsValueType)
                    {
                        body.Instructions.Add(CilOpCodes.Box, m.DeclaringType);
                    }
                }
                else
                {
                    TypeSignature pType = sig.ParameterTypes[sig.HasThis ? i - 1 : i];
                    if (pType.IsValueType)
                    {
                        body.Instructions.Add(CilOpCodes.Box, pType.ToTypeDefOrRef());
                    }
                }
                body.Instructions.Add(CilOpCodes.Stelem_Ref);
            }
        }

        body.Instructions.Add(CilOpCodes.Call, rt.VmEngineRun);

        TypeSignature retType = sig.ReturnType;
        if (retType.ElementType == AsmResolver.PE.DotNet.Metadata.Tables.ElementType.Void)
        {
            body.Instructions.Add(CilOpCodes.Pop);
        }
        else if (retType.IsValueType)
        {
            body.Instructions.Add(CilOpCodes.Unbox_Any, retType.ToTypeDefOrRef());
        }
        else if (!SignatureComparer.Default.Equals(retType, cor.Object))
        {
            body.Instructions.Add(CilOpCodes.Castclass, retType.ToTypeDefOrRef());
        }

        body.Instructions.Add(CilOpCodes.Ret);
        body.Instructions.CalculateOffsets();
        m.CilMethodBody = body;
    }

    private static void BuildTokenInitializer(ModuleDefinition module, RuntimeHandles rt, TokenCollector tokens)
    {
        var cor = module.CorLibTypeFactory;
        var importer = module.DefaultImporter;

        ITypeDefOrRef typeRef = importer.ImportType(typeof(Type));
        ITypeDefOrRef mbRef = importer.ImportType(typeof(System.Reflection.MethodBase));
        ITypeDefOrRef fiRef = importer.ImportType(typeof(System.Reflection.FieldInfo));

        IMethodDescriptor getTypeFromHandle = importer.ImportMethod(
            typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle), new[] { typeof(RuntimeTypeHandle) })!);
        IMethodDescriptor getMethodFromHandle = importer.ImportMethod(
            typeof(System.Reflection.MethodBase).GetMethod(
                nameof(System.Reflection.MethodBase.GetMethodFromHandle),
                new[] { typeof(RuntimeMethodHandle), typeof(RuntimeTypeHandle) })!);
        IMethodDescriptor getFieldFromHandle = importer.ImportMethod(
            typeof(System.Reflection.FieldInfo).GetMethod(
                nameof(System.Reflection.FieldInfo.GetFieldFromHandle),
                new[] { typeof(RuntimeFieldHandle), typeof(RuntimeTypeHandle) })!);

        var body = new CilMethodBody(rt.TokenTableInit);
        var locTypes = new CilLocalVariable(typeRef.ToTypeSignature().MakeSzArrayType());
        var locMethods = new CilLocalVariable(mbRef.ToTypeSignature().MakeSzArrayType());
        var locFields = new CilLocalVariable(fiRef.ToTypeSignature().MakeSzArrayType());
        var locDefaultTypeHandle = new CilLocalVariable(importer.ImportType(typeof(RuntimeTypeHandle)).ToTypeSignature());
        body.LocalVariables.Add(locTypes);
        body.LocalVariables.Add(locMethods);
        body.LocalVariables.Add(locFields);
        body.LocalVariables.Add(locDefaultTypeHandle);

        body.Instructions.Add(CilOpCodes.Ldloca, locDefaultTypeHandle);
        body.Instructions.Add(CilOpCodes.Initobj, importer.ImportType(typeof(RuntimeTypeHandle)));

        // Types[]
        body.Instructions.Add(CilOpCodes.Ldc_I4, tokens.Types.Count);
        body.Instructions.Add(CilOpCodes.Newarr, typeRef);
        body.Instructions.Add(CilOpCodes.Stloc, locTypes);
        for (int i = 0; i < tokens.Types.Count; i++)
        {
            body.Instructions.Add(CilOpCodes.Ldloc, locTypes);
            body.Instructions.Add(CilOpCodes.Ldc_I4, i);
            body.Instructions.Add(CilOpCodes.Ldtoken, importer.ImportType(tokens.Types[i]));
            body.Instructions.Add(CilOpCodes.Call, getTypeFromHandle);
            body.Instructions.Add(CilOpCodes.Stelem_Ref);
        }
        body.Instructions.Add(CilOpCodes.Ldloc, locTypes);
        body.Instructions.Add(CilOpCodes.Stsfld, rt.TokenTypesField);

        // Methods[]
        body.Instructions.Add(CilOpCodes.Ldc_I4, tokens.Methods.Count);
        body.Instructions.Add(CilOpCodes.Newarr, mbRef);
        body.Instructions.Add(CilOpCodes.Stloc, locMethods);
        for (int i = 0; i < tokens.Methods.Count; i++)
        {
            IMethodDescriptor md = importer.ImportMethod(tokens.Methods[i]);
            body.Instructions.Add(CilOpCodes.Ldloc, locMethods);
            body.Instructions.Add(CilOpCodes.Ldc_I4, i);
            body.Instructions.Add(CilOpCodes.Ldtoken, md);
            if (md.DeclaringType != null)
            {
                ITypeDefOrRef declRef = md.DeclaringType is TypeSpecification ts
                    ? importer.ImportTypeSignature(ts.Signature!).ToTypeDefOrRef()
                    : importer.ImportType((ITypeDefOrRef)md.DeclaringType);
                body.Instructions.Add(CilOpCodes.Ldtoken, declRef);
            }
            else
            {
                body.Instructions.Add(CilOpCodes.Ldloc, locDefaultTypeHandle);
            }
            body.Instructions.Add(CilOpCodes.Call, getMethodFromHandle);
            body.Instructions.Add(CilOpCodes.Stelem_Ref);
        }
        body.Instructions.Add(CilOpCodes.Ldloc, locMethods);
        body.Instructions.Add(CilOpCodes.Stsfld, rt.TokenMethodsField);

        // Fields[]
        body.Instructions.Add(CilOpCodes.Ldc_I4, tokens.Fields.Count);
        body.Instructions.Add(CilOpCodes.Newarr, fiRef);
        body.Instructions.Add(CilOpCodes.Stloc, locFields);
        for (int i = 0; i < tokens.Fields.Count; i++)
        {
            IFieldDescriptor fd = importer.ImportField(tokens.Fields[i]);
            body.Instructions.Add(CilOpCodes.Ldloc, locFields);
            body.Instructions.Add(CilOpCodes.Ldc_I4, i);
            body.Instructions.Add(CilOpCodes.Ldtoken, fd);
            if (fd.DeclaringType != null)
            {
                ITypeDefOrRef declRef = fd.DeclaringType is TypeSpecification ts
                    ? importer.ImportTypeSignature(ts.Signature!).ToTypeDefOrRef()
                    : importer.ImportType((ITypeDefOrRef)fd.DeclaringType);
                body.Instructions.Add(CilOpCodes.Ldtoken, declRef);
            }
            else
            {
                body.Instructions.Add(CilOpCodes.Ldloc, locDefaultTypeHandle);
            }
            body.Instructions.Add(CilOpCodes.Call, getFieldFromHandle);
            body.Instructions.Add(CilOpCodes.Stelem_Ref);
        }
        body.Instructions.Add(CilOpCodes.Ldloc, locFields);
        body.Instructions.Add(CilOpCodes.Stsfld, rt.TokenFieldsField);

        body.Instructions.Add(CilOpCodes.Ret);
        body.Instructions.CalculateOffsets();
        rt.TokenTableInit.CilMethodBody = body;
    }
}
