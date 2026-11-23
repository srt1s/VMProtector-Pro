using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace VMProtector.Core.Passes;

internal static class ConstantMutationPass
{
    public static int Execute(ModuleDefinition module, RuntimeHandles rt)
    {
        int mutated = 0;

        foreach (TypeDefinition type in module.GetAllTypes())
        {
            if (rt.RuntimeTypes.Contains(type) || type.IsModuleType) continue;
            foreach (MethodDefinition m in type.Methods)
            {
                if (m.CilMethodBody == null) continue;
                CilMethodBody body = m.CilMethodBody;
                if (body.Instructions.Count < 4) continue;

                body.Instructions.ExpandMacros();
                CilInstructionCollection insns = body.Instructions;

                for (int i = 0; i < insns.Count; i++)
                {
                    CilInstruction insn = insns[i];
                    if (insn.OpCode.Code != CilCode.Ldc_I4 || insn.Operand is not int val) continue;
                    // Mutate non-trivial integers (avoid tiny switch indices/bools to keep IL clean & fast)
                    if (val is >= -1 and <= 8) continue;
                    if (mutated >= 8000) break;

                    int k1 = CryptoUtils.RandomInt();
                    int k2 = CryptoUtils.RandomInt();
                    // val == ((val ^ k1) + k2) - k2 ^ k1
                    int inner = unchecked((val ^ k1) + k2);

                    // Replace insn in-place so existing branch labels pointing to insn remain intact
                    insn.OpCode = CilOpCodes.Ldc_I4;
                    insn.Operand = inner;
                    insns.Insert(i + 1, new CilInstruction(CilOpCodes.Ldc_I4, k2));
                    insns.Insert(i + 2, new CilInstruction(CilOpCodes.Sub));
                    insns.Insert(i + 3, new CilInstruction(CilOpCodes.Ldc_I4, k1));
                    insns.Insert(i + 4, new CilInstruction(CilOpCodes.Xor));

                    i += 4;
                    mutated++;
                }

                insns.OptimizeMacros();
                insns.CalculateOffsets();
            }
        }

        return mutated;
    }
}
