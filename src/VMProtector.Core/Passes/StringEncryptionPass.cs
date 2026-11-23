using System.Text;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace VMProtector.Core.Passes;

internal static class StringEncryptionPass
{
    public static int Execute(ModuleDefinition module, RuntimeHandles rt, ProtectionOptions options)
    {
        var stringToId = new Dictionary<string, int>(StringComparer.Ordinal);
        var orderedStrings = new List<string>();
        var sites = new List<(CilMethodBody body, CilInstruction insn, int id)>();

        foreach (TypeDefinition type in module.GetAllTypes())
        {
            if (rt.RuntimeTypes.Contains(type) || type.IsModuleType) continue;
            foreach (MethodDefinition m in type.Methods)
            {
                if (m.CilMethodBody == null) continue;
                var body = m.CilMethodBody;
                foreach (CilInstruction insn in body.Instructions)
                {
                    if (insn.OpCode.Code == CilCode.Ldstr && insn.Operand is string s && s.Length > 0)
                    {
                        if (!stringToId.TryGetValue(s, out int id))
                        {
                            id = orderedStrings.Count;
                            stringToId[s] = id;
                            orderedStrings.Add(s);
                        }
                        sites.Add((body, insn, id));
                    }
                }
            }
        }

        if (orderedStrings.Count == 0)
        {
            RuntimeInjector.PatchReturnString(rt.CfgGetStringResource, "");
            return 0;
        }

        using var blobMs = new MemoryStream();
        var offsets = new int[orderedStrings.Count];
        var lengths = new int[orderedStrings.Count];
        for (int i = 0; i < orderedStrings.Count; i++)
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(orderedStrings[i]);
            offsets[i] = (int)blobMs.Position;
            lengths[i] = utf8.Length;
            blobMs.Write(utf8, 0, utf8.Length);
        }

        byte[] rawBlob = blobMs.ToArray();
        using var plainMs = new MemoryStream();
        using (var bw = new BinaryWriter(plainMs, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write(orderedStrings.Count);
            for (int i = 0; i < orderedStrings.Count; i++)
            {
                bw.Write(offsets[i]);
                bw.Write(lengths[i]);
            }
            bw.Write(rawBlob.Length);
            bw.Write(rawBlob);
        }

        byte[] key = CryptoUtils.RandomBytes(32);
        byte[] nonce = CryptoUtils.RandomBytes(12);
        byte[] enc = CryptoUtils.ChaCha20Xor(key, nonce, 1u, plainMs.ToArray());

        string resName = "." + CryptoUtils.RandomIdentifier(12);
        module.Resources.Add(new ManifestResource(resName, ManifestResourceAttributes.Private, new DataSegment(enc)));

        RuntimeInjector.PatchReturnString(rt.CfgGetStringResource, resName);
        RuntimeInjector.PatchReturnObfuscatedByteArray(rt.CfgGetStringKey, key);
        RuntimeInjector.PatchReturnObfuscatedByteArray(rt.CfgGetStringNonce, nonce);

        // Replace ldstr with Vault.Get(encodedId, salt) while preserving branch targets
        foreach (var group in sites.GroupBy(x => x.body))
        {
            CilInstructionCollection insns = group.Key.Instructions;
            foreach (var site in group)
            {
                int idx = insns.IndexOf(site.insn);
                if (idx < 0) continue;

                int salt = CryptoUtils.RandomInt();
                int encodedId = site.id ^ salt;

                // Keep original CilInstruction object as the first instruction so branch labels stay valid!
                site.insn.OpCode = CilOpCodes.Ldc_I4;
                site.insn.Operand = encodedId;

                insns.Insert(idx + 1, new CilInstruction(CilOpCodes.Ldc_I4, salt));
                insns.Insert(idx + 2, new CilInstruction(CilOpCodes.Call, rt.StringVaultGet));
            }
            insns.CalculateOffsets();
        }

        return sites.Count;
    }
}
