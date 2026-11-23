using System.Runtime.InteropServices;
using System.Security.Cryptography;
using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.File;

namespace VMProtector.Core.Passes;

internal static class NativePeProtector
{
    private enum NativeVmOp : byte
    {
        Nop         = 0x00,
        PushImm64   = 0x01,
        LoadReg     = 0x02,
        StoreReg    = 0x03,
        Add64       = 0x04,
        Sub64       = 0x05,
        Xor64       = 0x06,
        Mul64       = 0x07,
        Rol64       = 0x08,
        Ror64       = 0x09,
        ProbeDebug  = 0x0A,
        EmitKeyWord = 0x0B,
        MixHash     = 0x0C,
        Dup         = 0x0D,
        Swap        = 0x0E,
        Halt        = 0xFF
    }

    public static void ProtectNativePe64(string inputPath, string outputPath, ProtectionOptions options)
    {
        byte[] targetRaw = File.ReadAllBytes(inputPath);
        PEFile targetPe = PEFile.FromBytes(targetRaw);
        if (targetPe.FileHeader.Machine != MachineType.Amd64)
        {
            throw new NotSupportedException($"Native PE protector supports x64 (Amd64) binaries. Detected: {targetPe.FileHeader.Machine}");
        }

        bool isGui = targetPe.OptionalHeader.SubSystem == SubSystem.WindowsGui;
        byte[] stubRaw = EmbeddedAssets.LoadNativeStubBytes(isGui);
        PEFile stubPe = PEFile.FromBytes(stubRaw);

        // Build per-build ChaCha20 key & nonce
        byte[] key = CryptoUtils.RandomBytes(32);
        byte[] nonce = CryptoUtils.RandomBytes(12);
        uint payloadCrc = CryptoUtils.Crc32(targetRaw);
        byte[] encPayload = CryptoUtils.ChaCha20Xor(key, nonce, 1u, targetRaw);

        // Build per-build randomized 256-entry opcode permutation
        NativeVmOp[] usedOps = Enum.GetValues<NativeVmOp>();
        byte[] physPool = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        Random.Shared.Shuffle(physPool);

        var encMap = new Dictionary<NativeVmOp, byte>(usedOps.Length);
        byte[] opcodeMap = new byte[256];
        for (int i = 0; i < usedOps.Length; i++)
        {
            byte phys = physPool[i];
            encMap[usedOps[i]] = phys;
            opcodeMap[phys] = (byte)usedOps[i];
        }

        // Compile a custom C++20 VM program that constructs each 64-bit key word inside VM registers
        // and silently XOR-taints them with ProbeDebug()!
        byte[] vmSalt = CryptoUtils.RandomBytes(16);
        byte[] plainVmCode = CompileKeyDerivationVmProgram(key, encMap);
        uint vmCrc = CryptoUtils.Crc32(plainVmCode);

        byte[] encVmCode = new byte[plainVmCode.Length];
        for (int i = 0; i < plainVmCode.Length; i++)
        {
            encVmCode[i] = (byte)(plainVmCode[i] ^ vmSalt[i & 15] ^ ((i * 0x5D) & 0xFF));
        }

        // Assemble VmpSectionBundleHeader + encVmCode + encPayload
        using var secMs = new MemoryStream();
        using (var bw = new BinaryWriter(secMs))
        {
            bw.Write(0x58504D56u);                         // magic = 'VMPX'
            bw.Write((ushort)2);                           // version
            bw.Write((ushort)(options.EnableAntiDebug ? 1 : 0)); // flags
            bw.Write(opcodeMap);                           // 256 bytes
            bw.Write(vmSalt);                              // 16 bytes
            bw.Write((uint)encVmCode.Length);
            bw.Write(vmCrc);
            bw.Write(nonce);                               // 12 bytes
            bw.Write((uint)encPayload.Length);
            bw.Write(payloadCrc);
            bw.Write(0UL);                                 // expectedDebugMask
            bw.Write(encVmCode);
            bw.Write(encPayload);
        }

        byte[] sectionBytes = secMs.ToArray();

        // Append .vmpx section cleanly to the C++20 Native Stub PE
        var vmpxSection = new PESection(
            ".vmpx",
            SectionFlags.MemoryRead | SectionFlags.ContentInitializedData,
            new DataSegment(sectionBytes));

        stubPe.Sections.Add(vmpxSection);
        stubPe.UpdateHeaders();

        // Write output
        string? outDir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(outDir)) Directory.CreateDirectory(outDir);

        using var fs = File.Create(outputPath);
        stubPe.Write(fs);
    }

    private static byte[] CompileKeyDerivationVmProgram(byte[] key32, Dictionary<NativeVmOp, byte> encMap)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        // Emit randomized arithmetic instructions for each of the 4 64-bit words of the ChaCha20 key
        for (int w = 0; w < 4; w++)
        {
            ulong targetWord = BitConverter.ToUInt64(key32, w * 8);
            ulong maskA = BitConverter.ToUInt64(CryptoUtils.RandomBytes(8), 0);
            int rot = RandomNumberGenerator.GetInt32(1, 63);
            ulong addDelta = BitConverter.ToUInt64(CryptoUtils.RandomBytes(8), 0);

            // Inverse transform: ((targetWord + addDelta) rotated right by rot) ^ maskA
            ulong preRot = unchecked(targetWord + addDelta);
            ulong rotatedBack = (preRot >> rot) | (preRot << (64 - rot));
            ulong seedVal = rotatedBack ^ maskA;

            // VM computes: rotl64(seedVal ^ maskA, rot) - addDelta ^ ProbeDebug() == targetWord (when clean!)
            bw.Write(encMap[NativeVmOp.PushImm64]);
            bw.Write(seedVal);
            bw.Write(encMap[NativeVmOp.PushImm64]);
            bw.Write(maskA);
            bw.Write(encMap[NativeVmOp.Xor64]);
            bw.Write(encMap[NativeVmOp.Rol64]);
            bw.Write((byte)rot);
            bw.Write(encMap[NativeVmOp.PushImm64]);
            bw.Write(addDelta);
            bw.Write(encMap[NativeVmOp.Sub64]);

            // Mix anti-debug probe word directly into key calculation (0 when clean, poison when debugged)
            bw.Write(encMap[NativeVmOp.ProbeDebug]);
            bw.Write(encMap[NativeVmOp.Xor64]);

            bw.Write(encMap[NativeVmOp.StoreReg]);
            bw.Write((byte)w);
            bw.Write(encMap[NativeVmOp.LoadReg]);
            bw.Write((byte)w);

            bw.Write(encMap[NativeVmOp.EmitKeyWord]);
            bw.Write((byte)w);
        }

        bw.Write(encMap[NativeVmOp.Halt]);
        bw.Flush();
        return ms.ToArray();
    }
}
