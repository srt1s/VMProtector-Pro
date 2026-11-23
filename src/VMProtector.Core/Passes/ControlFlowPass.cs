using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace VMProtector.Core.Passes;

internal static class ControlFlowPass
{
    public static int Execute(ModuleDefinition module, RuntimeHandles rt)
    {
        int flattened = 0;

        foreach (TypeDefinition type in module.GetAllTypes())
        {
            if (rt.RuntimeTypes.Contains(type) || type.IsModuleType) continue;
            foreach (MethodDefinition m in type.Methods)
            {
                if (!m.HasMethodBody || m.CilMethodBody == null) continue;
                if (m.IsConstructor || m.IsRuntimeSpecialName) continue;
                CilMethodBody body = m.CilMethodBody;
                if (body.ExceptionHandlers.Count > 0 || body.Instructions.Count < 8) continue;

                // Skip tiny VM stubs (they already call VmEngine.Run)
                if (body.Instructions.Count <= 12 &&
                    body.Instructions.Any(i => i.OpCode.Code == CilCode.Call && ReferenceEquals(i.Operand, rt.VmEngineRun)))
                {
                    continue;
                }

                if (TryFlattenMethod(module, body))
                {
                    flattened++;
                }
            }
        }

        return flattened;
    }

    private static bool TryFlattenMethod(ModuleDefinition module, CilMethodBody body)
    {
        body.Instructions.ExpandMacros();
        var orig = body.Instructions;

        // Collect all branch targets so we never break inside a branch target span
        var branchTargets = new HashSet<CilInstruction>();
        foreach (CilInstruction insn in orig)
        {
            if (insn.Operand is CilInstructionLabel lbl && lbl.Instruction != null)
            {
                branchTargets.Add(lbl.Instruction);
            }
            else if (insn.Operand is IList<ICilLabel> sw)
            {
                foreach (ICilLabel l in sw)
                {
                    if (l is CilInstructionLabel sl && sl.Instruction != null)
                    {
                        branchTargets.Add(sl.Instruction);
                    }
                }
            }
        }

        // Compute stack depth before each instruction via simple forward walk along instruction stream
        int[] stackDepthBefore = new int[orig.Count];
        bool[] reachable = new bool[orig.Count];
        var work = new Queue<int>();
        var insnIndex = new Dictionary<CilInstruction, int>(orig.Count);
        for (int i = 0; i < orig.Count; i++) insnIndex[orig[i]] = i;

        reachable[0] = true;
        work.Enqueue(0);

        while (work.Count > 0)
        {
            int idx = work.Dequeue();
            int depth = stackDepthBefore[idx];
            CilInstruction insn = orig[idx];

            int pop = insn.GetStackPopCount(body);
            int push = insn.GetStackPushCount();
            if (pop < 0) pop = depth; // e.g., leave clears stack
            int nextDepth = depth - pop + push;
            if (nextDepth < 0 || nextDepth > 128) return false;

            void EnqueueTarget(CilInstruction target)
            {
                if (!insnIndex.TryGetValue(target, out int tidx)) return;
                if (!reachable[tidx])
                {
                    reachable[tidx] = true;
                    stackDepthBefore[tidx] = nextDepth;
                    work.Enqueue(tidx);
                }
                else if (stackDepthBefore[tidx] != nextDepth)
                {
                    // Divergent stack depth: skip conservatively
                    reachable[tidx] = true;
                }
            }

            CilFlowControl fc = insn.OpCode.FlowControl;
            if (insn.Operand is CilInstructionLabel tLbl && tLbl.Instruction != null)
            {
                EnqueueTarget(tLbl.Instruction);
            }
            else if (insn.Operand is IList<ICilLabel> swList)
            {
                foreach (ICilLabel l in swList)
                {
                    if (l is CilInstructionLabel sl && sl.Instruction != null) EnqueueTarget(sl.Instruction);
                }
            }

            if (fc != CilFlowControl.Branch && fc != CilFlowControl.Return && fc != CilFlowControl.Throw)
            {
                if (idx + 1 < orig.Count)
                {
                    if (!reachable[idx + 1])
                    {
                        reachable[idx + 1] = true;
                        stackDepthBefore[idx + 1] = nextDepth;
                        work.Enqueue(idx + 1);
                    }
                }
            }
        }

        // Split into basic blocks strictly at stack-depth == 0 points after unconditional flow or at branch targets
        var blocks = new List<List<CilInstruction>>();
        var current = new List<CilInstruction>();
        for (int i = 0; i < orig.Count; i++)
        {
            if (i > 0 && current.Count > 0 && reachable[i] && stackDepthBefore[i] == 0)
            {
                CilFlowControl prevFc = orig[i - 1].OpCode.FlowControl;
                if (prevFc == CilFlowControl.Branch || prevFc == CilFlowControl.Return || prevFc == CilFlowControl.Throw || branchTargets.Contains(orig[i]))
                {
                    blocks.Add(current);
                    current = new List<CilInstruction>();
                }
            }
            current.Add(orig[i]);
        }
        if (current.Count > 0) blocks.Add(current);

        if (blocks.Count < 3)
        {
            orig.OptimizeMacros();
            return false;
        }

        // Map each block's entry instruction to its state id
        var blockStateIds = new Dictionary<CilInstruction, int>(blocks.Count);
        for (int b = 0; b < blocks.Count; b++)
        {
            blockStateIds[blocks[b][0]] = b;
        }

        int keySalt = CryptoUtils.RandomInt();
        var stateVar = new CilLocalVariable(module.CorLibTypeFactory.Int32);
        var opaqueVar = new CilLocalVariable(module.CorLibTypeFactory.Int32);
        body.LocalVariables.Add(stateVar);
        body.LocalVariables.Add(opaqueVar);

        // Shuffle non-entry blocks (keep block 0 first in dispatch mapping, though physically shuffled!)
        int[] physOrder = Enumerable.Range(0, blocks.Count).ToArray();
        Random.Shared.Shuffle(physOrder);

        var switchLabels = new ICilLabel[blocks.Count];
        var dispatchEntryLabels = new CilInstruction[blocks.Count];

        var newInsns = new List<CilInstruction>();
        // Initialize stateVar = 0 ^ keySalt
        var initOpaque = new CilInstruction(CilOpCodes.Ldc_I4, CryptoUtils.RandomInt());
        newInsns.Add(initOpaque);
        newInsns.Add(new CilInstruction(CilOpCodes.Stloc, opaqueVar));
        newInsns.Add(new CilInstruction(CilOpCodes.Ldc_I4, 0 ^ keySalt));
        newInsns.Add(new CilInstruction(CilOpCodes.Stloc, stateVar));

        // Dispatcher head
        var dispatchHead = new CilInstruction(CilOpCodes.Ldloc, stateVar);
        newInsns.Add(dispatchHead);
        newInsns.Add(new CilInstruction(CilOpCodes.Ldc_I4, keySalt));
        newInsns.Add(new CilInstruction(CilOpCodes.Xor));

        var switchInsn = new CilInstruction(CilOpCodes.Switch, switchLabels);
        newInsns.Add(switchInsn);

        // Default fallthrough (unreachable trap / opaque loop back to block 0)
        newInsns.Add(new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(dispatchHead)));

        // Emit shuffled blocks
        foreach (int bIdx in physOrder)
        {
            List<CilInstruction> blk = blocks[bIdx];
            CilInstruction first = blk[0];
            dispatchEntryLabels[bIdx] = first;
            switchLabels[bIdx] = new CilInstructionLabel(first);

            // Inject harmless opaque predicate block before body if stack is 0:
            // if ((opaqueVar & 1) == 0 && (opaqueVar * (opaqueVar + 1) & 1) != 0) -> impossible!
            newInsns.AddRange(blk);

            CilInstruction last = blk[^1];
            CilFlowControl lastFc = last.OpCode.FlowControl;
            if (lastFc != CilFlowControl.Branch && lastFc != CilFlowControl.Return && lastFc != CilFlowControl.Throw)
            {
                int nextBlockId = bIdx + 1;
                if (nextBlockId < blocks.Count)
                {
                    newInsns.Add(new CilInstruction(CilOpCodes.Ldc_I4, nextBlockId ^ keySalt));
                    newInsns.Add(new CilInstruction(CilOpCodes.Stloc, stateVar));

                    // Opaque check: ((x * (x + 1)) & 1) is ALWAYS 0 -> always takes branch to dispatchHead
                    newInsns.Add(new CilInstruction(CilOpCodes.Ldloc, opaqueVar));
                    newInsns.Add(new CilInstruction(CilOpCodes.Dup));
                    newInsns.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                    newInsns.Add(new CilInstruction(CilOpCodes.Add));
                    newInsns.Add(new CilInstruction(CilOpCodes.Mul));
                    newInsns.Add(new CilInstruction(CilOpCodes.Ldc_I4_1));
                    newInsns.Add(new CilInstruction(CilOpCodes.And));
                    newInsns.Add(new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel(dispatchHead)));
                    newInsns.Add(new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(dispatchHead)));
                }
            }
        }

        orig.Clear();
        foreach (CilInstruction insn in newInsns) orig.Add(insn);

        orig.OptimizeMacros();
        orig.CalculateOffsets();
        return true;
    }
}
