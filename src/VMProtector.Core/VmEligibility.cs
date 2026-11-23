using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace VMProtector.Core;

internal static class VmEligibility
{
    public static bool IsEligible(MethodDefinition m, out string reason)
    {
        reason = "";
        if (!m.HasMethodBody || m.CilMethodBody == null)
        {
            reason = "no_body";
            return false;
        }
        if (m.IsConstructor || m.IsRuntimeSpecialName || m.IsSpecialName && (m.Name == "InitializeComponent" || m.Name == "Connect"))
        {
            reason = "special";
            return false;
        }
        if (m.Name == "InitializeComponent" || m.Name == "Connect" || m.Name == "MoveNext" || m.Name == "Main")
        {
            reason = "wpf_or_entry";
            return false;
        }
        if (m.GenericParameters.Count > 0 || (m.DeclaringType?.GenericParameters.Count ?? 0) > 0)
        {
            reason = "generic";
            return false;
        }
        if (m.Signature == null)
        {
            reason = "no_sig";
            return false;
        }
        if (HasUnsupportedTypeSig(m.Signature.ReturnType))
        {
            reason = "unsupported_ret";
            return false;
        }
        foreach (TypeSignature pt in m.Signature.ParameterTypes)
        {
            if (HasUnsupportedTypeSig(pt))
            {
                reason = "unsupported_param";
                return false;
            }
        }

        CilMethodBody body = m.CilMethodBody;
        if (body.ExceptionHandlers.Count > 0)
        {
            reason = "eh";
            return false;
        }
        if (body.Instructions.Count < 3)
        {
            reason = "too_small";
            return false;
        }
        foreach (CilLocalVariable loc in body.LocalVariables)
        {
            if (HasUnsupportedTypeSig(loc.VariableType))
            {
                reason = "unsupported_local";
                return false;
            }
        }

        foreach (CilInstruction insn in body.Instructions)
        {
            CilCode c = insn.OpCode.Code;
            if (!IsSupportedOpCode(c))
            {
                reason = $"op_{c}";
                return false;
            }

            if (insn.Operand is IMethodDescriptor md)
            {
                if (md is MethodSpecification || (md.Signature != null && (md.Signature.GenericParameterCount > 0 || HasUnsupportedMethodSig(md.Signature))))
                {
                    reason = "call_generic_or_ref";
                    return false;
                }
                if (md.DeclaringType is TypeSpecification)
                {
                    reason = "call_typespec";
                    return false;
                }
            }
            else if (insn.Operand is IFieldDescriptor fd)
            {
                if (fd.DeclaringType is TypeSpecification)
                {
                    reason = "fld_typespec";
                    return false;
                }
                if (fd.Signature != null && HasUnsupportedTypeSig(fd.Signature.FieldType))
                {
                    reason = "fld_sig";
                    return false;
                }
            }
            else if (insn.Operand is TypeSpecification ts && HasUnsupportedTypeSig(ts.Signature))
            {
                reason = "typespec";
                return false;
            }
        }

        return true;
    }

    private static bool HasUnsupportedMethodSig(MethodSignature sig)
    {
        if (HasUnsupportedTypeSig(sig.ReturnType)) return true;
        foreach (TypeSignature p in sig.ParameterTypes)
        {
            if (HasUnsupportedTypeSig(p)) return true;
        }
        return false;
    }

    private static bool HasUnsupportedTypeSig(TypeSignature? sig)
    {
        if (sig == null) return true;
        if (sig is ByReferenceTypeSignature or PointerTypeSignature or FunctionPointerTypeSignature
            or GenericParameterSignature or PinnedTypeSignature)
        {
            return true;
        }
        if (sig is GenericInstanceTypeSignature gi)
        {
            foreach (TypeSignature arg in gi.TypeArguments)
            {
                if (HasUnsupportedTypeSig(arg)) return true;
            }
        }
        if (sig is SzArrayTypeSignature sz) return HasUnsupportedTypeSig(sz.BaseType);
        if (sig is CustomModifierTypeSignature cm) return HasUnsupportedTypeSig(cm.BaseType);
        return false;
    }

    private static bool IsSupportedOpCode(CilCode code)
    {
        return code switch
        {
            CilCode.Nop or
            CilCode.Ldc_I4 or CilCode.Ldc_I4_S or CilCode.Ldc_I4_M1 or
            CilCode.Ldc_I4_0 or CilCode.Ldc_I4_1 or CilCode.Ldc_I4_2 or CilCode.Ldc_I4_3 or
            CilCode.Ldc_I4_4 or CilCode.Ldc_I4_5 or CilCode.Ldc_I4_6 or CilCode.Ldc_I4_7 or CilCode.Ldc_I4_8 or
            CilCode.Ldc_I8 or CilCode.Ldc_R4 or CilCode.Ldc_R8 or
            CilCode.Ldnull or CilCode.Ldstr or
            CilCode.Ldarg or CilCode.Ldarg_S or CilCode.Ldarg_0 or CilCode.Ldarg_1 or CilCode.Ldarg_2 or CilCode.Ldarg_3 or
            CilCode.Starg or CilCode.Starg_S or
            CilCode.Ldloc or CilCode.Ldloc_S or CilCode.Ldloc_0 or CilCode.Ldloc_1 or CilCode.Ldloc_2 or CilCode.Ldloc_3 or
            CilCode.Stloc or CilCode.Stloc_S or CilCode.Stloc_0 or CilCode.Stloc_1 or CilCode.Stloc_2 or CilCode.Stloc_3 or
            CilCode.Dup or CilCode.Pop or
            CilCode.Add or CilCode.Add_Ovf or CilCode.Add_Ovf_Un or
            CilCode.Sub or CilCode.Sub_Ovf or CilCode.Sub_Ovf_Un or
            CilCode.Mul or CilCode.Mul_Ovf or CilCode.Mul_Ovf_Un or
            CilCode.Div or CilCode.Div_Un or CilCode.Rem or CilCode.Rem_Un or
            CilCode.Neg or CilCode.Not or CilCode.And or CilCode.Or or CilCode.Xor or
            CilCode.Shl or CilCode.Shr or CilCode.Shr_Un or
            CilCode.Conv_I1 or CilCode.Conv_U1 or CilCode.Conv_I2 or CilCode.Conv_U2 or
            CilCode.Conv_I4 or CilCode.Conv_U4 or CilCode.Conv_I8 or CilCode.Conv_U8 or
            CilCode.Conv_R4 or CilCode.Conv_R8 or CilCode.Conv_R_Un or
            CilCode.Ceq or CilCode.Cgt or CilCode.Cgt_Un or CilCode.Clt or CilCode.Clt_Un or
            CilCode.Br or CilCode.Br_S or
            CilCode.Brtrue or CilCode.Brtrue_S or
            CilCode.Brfalse or CilCode.Brfalse_S or
            CilCode.Beq or CilCode.Beq_S or
            CilCode.Bne_Un or CilCode.Bne_Un_S or
            CilCode.Bge or CilCode.Bge_S or CilCode.Bge_Un or CilCode.Bge_Un_S or
            CilCode.Bgt or CilCode.Bgt_S or CilCode.Bgt_Un or CilCode.Bgt_Un_S or
            CilCode.Ble or CilCode.Ble_S or CilCode.Ble_Un or CilCode.Ble_Un_S or
            CilCode.Blt or CilCode.Blt_S or CilCode.Blt_Un or CilCode.Blt_Un_S or
            CilCode.Switch or
            CilCode.Ldfld or CilCode.Stfld or CilCode.Ldsfld or CilCode.Stsfld or
            CilCode.Call or CilCode.Callvirt or CilCode.Newobj or
            CilCode.Castclass or CilCode.Isinst or CilCode.Box or CilCode.Unbox_Any or
            CilCode.Newarr or CilCode.Ldlen or
            CilCode.Ldelem_I1 or CilCode.Ldelem_U1 or CilCode.Ldelem_I2 or CilCode.Ldelem_U2 or
            CilCode.Ldelem_I4 or CilCode.Ldelem_U4 or CilCode.Ldelem_I8 or CilCode.Ldelem_R4 or CilCode.Ldelem_R8 or
            CilCode.Ldelem_Ref or CilCode.Ldelem or
            CilCode.Stelem_I1 or CilCode.Stelem_I2 or CilCode.Stelem_I4 or CilCode.Stelem_I8 or
            CilCode.Stelem_R4 or CilCode.Stelem_R8 or CilCode.Stelem_Ref or CilCode.Stelem or
            CilCode.Ldtoken or CilCode.Throw or CilCode.Ret => true,
            _ => false
        };
    }
}
