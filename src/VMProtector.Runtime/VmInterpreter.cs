using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace VMProtector.Runtime
{
    internal enum VmOp : byte
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

    internal static class VmEngine
    {
        private enum SlotKind : byte
        {
            Null = 0,
            I4 = 1,
            I8 = 2,
            R4 = 3,
            R8 = 4,
            Obj = 5
        }

        private struct VSlot
        {
            public SlotKind Kind;
            public long I64;
            public double R64;
            public object? Obj;

            public static VSlot FromNull() => new VSlot { Kind = SlotKind.Null };
            public static VSlot FromI4(int v) => new VSlot { Kind = SlotKind.I4, I64 = v };
            public static VSlot FromI8(long v) => new VSlot { Kind = SlotKind.I8, I64 = v };
            public static VSlot FromR4(float v) => new VSlot { Kind = SlotKind.R4, R64 = v };
            public static VSlot FromR8(double v) => new VSlot { Kind = SlotKind.R8, R64 = v };

            public static VSlot FromObject(object? obj, Type? hintType = null)
            {
                if (obj == null) return FromNull();
                Type t = hintType ?? obj.GetType();
                if (t.IsEnum) t = Enum.GetUnderlyingType(t);
                if (t == typeof(bool)) return FromI4((bool)obj ? 1 : 0);
                if (t == typeof(sbyte)) return FromI4((sbyte)obj);
                if (t == typeof(byte)) return FromI4((byte)obj);
                if (t == typeof(short)) return FromI4((short)obj);
                if (t == typeof(ushort)) return FromI4((ushort)obj);
                if (t == typeof(char)) return FromI4((char)obj);
                if (t == typeof(int)) return FromI4((int)obj);
                if (t == typeof(uint)) return FromI4(unchecked((int)(uint)obj));
                if (t == typeof(long)) return FromI8((long)obj);
                if (t == typeof(ulong)) return FromI8(unchecked((long)(ulong)obj));
                if (t == typeof(float)) return FromR4((float)obj);
                if (t == typeof(double)) return FromR8((double)obj);
                return new VSlot { Kind = SlotKind.Obj, Obj = obj };
            }

            public int AsI4() => Kind == SlotKind.Obj && Obj != null ? Convert.ToInt32(Obj) : unchecked((int)I64);
            public long AsI8() => Kind == SlotKind.Obj && Obj != null ? Convert.ToInt64(Obj) : I64;
            public double AsR() => (Kind == SlotKind.R4 || Kind == SlotKind.R8) ? R64 : (Kind == SlotKind.I8 ? (double)I64 : (double)(int)I64);
            public bool AsBool() => Kind switch
            {
                SlotKind.Null => false,
                SlotKind.Obj => Obj != null,
                SlotKind.R4 or SlotKind.R8 => R64 != 0.0,
                _ => I64 != 0
            };

            public object? ToManagedObject(Type? targetType)
            {
                if (targetType == null || targetType == typeof(void)) return ToUntypedObject();
                if (targetType.IsByRef) targetType = targetType.GetElementType()!;

                Type? nullableUnderlying = Nullable.GetUnderlyingType(targetType);
                if (Kind == SlotKind.Null)
                {
                    return null;
                }
                if (nullableUnderlying != null)
                {
                    object? inner = ToManagedObject(nullableUnderlying);
                    return inner == null ? null : Activator.CreateInstance(targetType, inner);
                }

                if (targetType.IsEnum)
                {
                    Type under = Enum.GetUnderlyingType(targetType);
                    object val = ToManagedObject(under)!;
                    return Enum.ToObject(targetType, val);
                }

                if (targetType == typeof(bool)) return AsBool();
                if (targetType == typeof(sbyte)) return unchecked((sbyte)AsI4());
                if (targetType == typeof(byte)) return unchecked((byte)AsI4());
                if (targetType == typeof(short)) return unchecked((short)AsI4());
                if (targetType == typeof(ushort)) return unchecked((ushort)AsI4());
                if (targetType == typeof(char)) return unchecked((char)AsI4());
                if (targetType == typeof(int)) return AsI4();
                if (targetType == typeof(uint)) return unchecked((uint)AsI4());
                if (targetType == typeof(long)) return AsI8();
                if (targetType == typeof(ulong)) return unchecked((ulong)AsI8());
                if (targetType == typeof(float)) return (float)AsR();
                if (targetType == typeof(double)) return AsR();

                return ToUntypedObject();
            }

            public object? ToUntypedObject()
            {
                return Kind switch
                {
                    SlotKind.Null => null,
                    SlotKind.I4 => unchecked((int)I64),
                    SlotKind.I8 => I64,
                    SlotKind.R4 => (float)R64,
                    SlotKind.R8 => R64,
                    _ => Obj
                };
            }
        }

        private sealed class VmMethodChunk
        {
            public int LocalCount;
            public int ReturnTypeSlot; // -1 for void, else index into TokenTable.Types
            public byte[] Bytecode = Array.Empty<byte>();
        }

        private static VmMethodChunk[]? _chunks;
        private static string[]? _strings;
        private static byte[]? _opcodeMap;
        private static readonly object _loadLock = new object();

        private static void EnsureLoaded()
        {
            if (_chunks != null) return;
            lock (_loadLock)
            {
                if (_chunks != null) return;
                SecurityGuard.Initialize(RuntimeConfig.GetSecurityFlags());
                TokenTable.EnsureInitialized();

                _opcodeMap = RuntimeConfig.GetOpcodeMap();
                string resName = RuntimeConfig.GetVmResource();

                Assembly asm = typeof(VmEngine).Assembly;
                using Stream? s = asm.GetManifestResourceStream(resName);
                if (s == null)
                {
                    _chunks = Array.Empty<VmMethodChunk>();
                    _strings = Array.Empty<string>();
                    return;
                }

                byte[] enc = new byte[s.Length];
                int read = 0;
                while (read < enc.Length)
                {
                    int n = s.Read(enc, read, enc.Length - read);
                    if (n <= 0) break;
                    read += n;
                }

                byte[] key = RuntimeConfig.GetVmKey();
                byte[] nonce = RuntimeConfig.GetVmNonce();
                uint poison = SecurityGuard.PoisonState;
                if (poison != 0 && key.Length > 1) key[1] ^= (byte)(poison & 0xFF);

                byte[] dec = CryptoCore.ChaCha20Xor(key, nonce, 1u, enc);
                Array.Clear(key, 0, key.Length);

                using var ms = new MemoryStream(dec);
                using var br = new BinaryReader(ms, Encoding.UTF8);

                int strCount = br.ReadInt32();
                string[] strs = new string[strCount];
                for (int i = 0; i < strCount; i++)
                {
                    int blen = br.ReadInt32();
                    strs[i] = blen == 0 ? string.Empty : Encoding.UTF8.GetString(br.ReadBytes(blen));
                }

                int methCount = br.ReadInt32();
                var chunks = new VmMethodChunk[methCount];
                for (int i = 0; i < methCount; i++)
                {
                    int locCount = br.ReadInt32();
                    int retSlot = br.ReadInt32();
                    int bcLen = br.ReadInt32();
                    byte[] bc = br.ReadBytes(bcLen);
                    chunks[i] = new VmMethodChunk
                    {
                        LocalCount = locCount,
                        ReturnTypeSlot = retSlot,
                        Bytecode = bc
                    };
                }

                _strings = strs;
                _chunks = chunks;
            }
        }

        private static Type ResolveType(int slot) => TokenTable.Types[slot];
        private static MethodBase ResolveMethod(int slot) => TokenTable.Methods[slot];
        private static FieldInfo ResolveField(int slot) => TokenTable.Fields[slot];

        public static object? Run(int encodedMethodId, int salt, object?[]? args)
        {
            EnsureLoaded();
            int methodId = encodedMethodId ^ salt;
            if (_chunks == null || _opcodeMap == null || methodId < 0 || methodId >= _chunks.Length)
            {
                throw new InvalidProgramException("Invalid VM target");
            }

            VmMethodChunk chunk = _chunks[methodId];
            byte[] code = chunk.Bytecode;
            byte[] opMap = _opcodeMap;
            VSlot[] stack = new VSlot[128];
            int sp = 0;

            VSlot[] locals = new VSlot[chunk.LocalCount];
            for (int i = 0; i < locals.Length; i++) locals[i] = VSlot.FromNull();

            VSlot[] argSlots = new VSlot[args != null ? args.Length : 0];
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    argSlots[i] = VSlot.FromObject(args[i]);
                }
            }

            int pc = 0;
            while (pc < code.Length)
            {
                byte phys = code[pc++];
                VmOp op = (VmOp)opMap[phys];

                switch (op)
                {
                    case VmOp.Nop:
                        break;

                    case VmOp.LdcI4:
                    {
                        int v = ReadI32(code, ref pc);
                        stack[sp++] = VSlot.FromI4(v);
                        break;
                    }
                    case VmOp.LdcI8:
                    {
                        long v = ReadI64(code, ref pc);
                        stack[sp++] = VSlot.FromI8(v);
                        break;
                    }
                    case VmOp.LdcR4:
                    {
                        float v = BitConverter.ToSingle(code, pc);
                        pc += 4;
                        stack[sp++] = VSlot.FromR4(v);
                        break;
                    }
                    case VmOp.LdcR8:
                    {
                        double v = BitConverter.ToDouble(code, pc);
                        pc += 8;
                        stack[sp++] = VSlot.FromR8(v);
                        break;
                    }
                    case VmOp.LdNull:
                        stack[sp++] = VSlot.FromNull();
                        break;

                    case VmOp.LdStr:
                    {
                        int idx = ReadI32(code, ref pc);
                        string sVal = (_strings != null && idx >= 0 && idx < _strings.Length) ? _strings[idx] : string.Empty;
                        stack[sp++] = VSlot.FromObject(sVal, typeof(string));
                        break;
                    }

                    case VmOp.LdArg:
                    {
                        int idx = ReadU16(code, ref pc);
                        stack[sp++] = argSlots[idx];
                        break;
                    }
                    case VmOp.StArg:
                    {
                        int idx = ReadU16(code, ref pc);
                        argSlots[idx] = stack[--sp];
                        break;
                    }
                    case VmOp.LdLoc:
                    {
                        int idx = ReadU16(code, ref pc);
                        stack[sp++] = locals[idx];
                        break;
                    }
                    case VmOp.StLoc:
                    {
                        int idx = ReadU16(code, ref pc);
                        locals[idx] = stack[--sp];
                        break;
                    }
                    case VmOp.Dup:
                    {
                        stack[sp] = stack[sp - 1];
                        sp++;
                        break;
                    }
                    case VmOp.Pop:
                        sp--;
                        break;

                    case VmOp.Add:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.R8 || b.Kind == SlotKind.R8) stack[sp++] = VSlot.FromR8(a.AsR() + b.AsR());
                        else if (a.Kind == SlotKind.R4 || b.Kind == SlotKind.R4) stack[sp++] = VSlot.FromR4((float)(a.AsR() + b.AsR()));
                        else if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(unchecked(a.AsI8() + b.AsI8()));
                        else stack[sp++] = VSlot.FromI4(unchecked(a.AsI4() + b.AsI4()));
                        break;
                    }
                    case VmOp.Sub:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.R8 || b.Kind == SlotKind.R8) stack[sp++] = VSlot.FromR8(a.AsR() - b.AsR());
                        else if (a.Kind == SlotKind.R4 || b.Kind == SlotKind.R4) stack[sp++] = VSlot.FromR4((float)(a.AsR() - b.AsR()));
                        else if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(unchecked(a.AsI8() - b.AsI8()));
                        else stack[sp++] = VSlot.FromI4(unchecked(a.AsI4() - b.AsI4()));
                        break;
                    }
                    case VmOp.Mul:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.R8 || b.Kind == SlotKind.R8) stack[sp++] = VSlot.FromR8(a.AsR() * b.AsR());
                        else if (a.Kind == SlotKind.R4 || b.Kind == SlotKind.R4) stack[sp++] = VSlot.FromR4((float)(a.AsR() * b.AsR()));
                        else if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(unchecked(a.AsI8() * b.AsI8()));
                        else stack[sp++] = VSlot.FromI4(unchecked(a.AsI4() * b.AsI4()));
                        break;
                    }
                    case VmOp.Div:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.R8 || b.Kind == SlotKind.R8) stack[sp++] = VSlot.FromR8(a.AsR() / b.AsR());
                        else if (a.Kind == SlotKind.R4 || b.Kind == SlotKind.R4) stack[sp++] = VSlot.FromR4((float)(a.AsR() / b.AsR()));
                        else if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(a.AsI8() / b.AsI8());
                        else stack[sp++] = VSlot.FromI4(a.AsI4() / b.AsI4());
                        break;
                    }
                    case VmOp.DivUn:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8)
                            stack[sp++] = VSlot.FromI8(unchecked((long)((ulong)a.AsI8() / (ulong)b.AsI8())));
                        else
                            stack[sp++] = VSlot.FromI4(unchecked((int)((uint)a.AsI4() / (uint)b.AsI4())));
                        break;
                    }
                    case VmOp.Rem:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.R8 || b.Kind == SlotKind.R8) stack[sp++] = VSlot.FromR8(a.AsR() % b.AsR());
                        else if (a.Kind == SlotKind.R4 || b.Kind == SlotKind.R4) stack[sp++] = VSlot.FromR4((float)(a.AsR() % b.AsR()));
                        else if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(a.AsI8() % b.AsI8());
                        else stack[sp++] = VSlot.FromI4(a.AsI4() % b.AsI4());
                        break;
                    }
                    case VmOp.RemUn:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8)
                            stack[sp++] = VSlot.FromI8(unchecked((long)((ulong)a.AsI8() % (ulong)b.AsI8())));
                        else
                            stack[sp++] = VSlot.FromI4(unchecked((int)((uint)a.AsI4() % (uint)b.AsI4())));
                        break;
                    }
                    case VmOp.Neg:
                    {
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.R8) stack[sp++] = VSlot.FromR8(-a.R64);
                        else if (a.Kind == SlotKind.R4) stack[sp++] = VSlot.FromR4((float)(-a.R64));
                        else if (a.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(unchecked(-a.AsI8()));
                        else stack[sp++] = VSlot.FromI4(unchecked(-a.AsI4()));
                        break;
                    }
                    case VmOp.Not:
                    {
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(~a.AsI8());
                        else stack[sp++] = VSlot.FromI4(~a.AsI4());
                        break;
                    }
                    case VmOp.And:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(a.AsI8() & b.AsI8());
                        else stack[sp++] = VSlot.FromI4(a.AsI4() & b.AsI4());
                        break;
                    }
                    case VmOp.Or:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(a.AsI8() | b.AsI8());
                        else stack[sp++] = VSlot.FromI4(a.AsI4() | b.AsI4());
                        break;
                    }
                    case VmOp.Xor:
                    {
                        VSlot b = stack[--sp];
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(a.AsI8() ^ b.AsI8());
                        else stack[sp++] = VSlot.FromI4(a.AsI4() ^ b.AsI4());
                        break;
                    }
                    case VmOp.Shl:
                    {
                        int shift = stack[--sp].AsI4();
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(a.AsI8() << (shift & 63));
                        else stack[sp++] = VSlot.FromI4(a.AsI4() << (shift & 31));
                        break;
                    }
                    case VmOp.Shr:
                    {
                        int shift = stack[--sp].AsI4();
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(a.AsI8() >> (shift & 63));
                        else stack[sp++] = VSlot.FromI4(a.AsI4() >> (shift & 31));
                        break;
                    }
                    case VmOp.ShrUn:
                    {
                        int shift = stack[--sp].AsI4();
                        VSlot a = stack[--sp];
                        if (a.Kind == SlotKind.I8) stack[sp++] = VSlot.FromI8(unchecked((long)((ulong)a.AsI8() >> (shift & 63))));
                        else stack[sp++] = VSlot.FromI4(unchecked((int)((uint)a.AsI4() >> (shift & 31))));
                        break;
                    }

                    case VmOp.ConvI1: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI4(unchecked((sbyte)(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (long)a.R64 : a.I64))); break; }
                    case VmOp.ConvU1: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI4(unchecked((byte)(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (long)a.R64 : a.I64))); break; }
                    case VmOp.ConvI2: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI4(unchecked((short)(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (long)a.R64 : a.I64))); break; }
                    case VmOp.ConvU2: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI4(unchecked((ushort)(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (long)a.R64 : a.I64))); break; }
                    case VmOp.ConvI4: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI4(unchecked((int)(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (long)a.R64 : a.I64))); break; }
                    case VmOp.ConvU4: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI4(unchecked((int)(uint)(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (ulong)(long)a.R64 : (ulong)a.I64))); break; }
                    case VmOp.ConvI8: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI8(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (long)a.R64 : a.AsI8()); break; }
                    case VmOp.ConvU8: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromI8(unchecked((long)(a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 ? (ulong)a.R64 : (ulong)a.AsI8()))); break; }
                    case VmOp.ConvR4: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromR4((float)a.AsR()); break; }
                    case VmOp.ConvR8: { VSlot a = stack[--sp]; stack[sp++] = VSlot.FromR8(a.AsR()); break; }

                    case VmOp.Ceq:
                    {
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        stack[sp++] = VSlot.FromI4(CompareEq(a, b) ? 1 : 0);
                        break;
                    }
                    case VmOp.Cgt:
                    {
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        stack[sp++] = VSlot.FromI4(CompareGt(a, b, false) ? 1 : 0);
                        break;
                    }
                    case VmOp.CgtUn:
                    {
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        stack[sp++] = VSlot.FromI4(CompareGt(a, b, true) ? 1 : 0);
                        break;
                    }
                    case VmOp.Clt:
                    {
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        stack[sp++] = VSlot.FromI4(CompareLt(a, b, false) ? 1 : 0);
                        break;
                    }
                    case VmOp.CltUn:
                    {
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        stack[sp++] = VSlot.FromI4(CompareLt(a, b, true) ? 1 : 0);
                        break;
                    }

                    case VmOp.Br:
                        pc = ReadI32(code, ref pc);
                        break;

                    case VmOp.BrTrue:
                    {
                        int target = ReadI32(code, ref pc);
                        if (stack[--sp].AsBool()) pc = target;
                        break;
                    }
                    case VmOp.BrFalse:
                    {
                        int target = ReadI32(code, ref pc);
                        if (!stack[--sp].AsBool()) pc = target;
                        break;
                    }
                    case VmOp.Beq:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (CompareEq(a, b)) pc = target;
                        break;
                    }
                    case VmOp.BneUn:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (!CompareEq(a, b)) pc = target;
                        break;
                    }
                    case VmOp.Bge:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (!CompareLt(a, b, false)) pc = target;
                        break;
                    }
                    case VmOp.BgeUn:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (!CompareLt(a, b, true)) pc = target;
                        break;
                    }
                    case VmOp.Bgt:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (CompareGt(a, b, false)) pc = target;
                        break;
                    }
                    case VmOp.BgtUn:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (CompareGt(a, b, true)) pc = target;
                        break;
                    }
                    case VmOp.Ble:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (!CompareGt(a, b, false)) pc = target;
                        break;
                    }
                    case VmOp.BleUn:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (!CompareGt(a, b, true)) pc = target;
                        break;
                    }
                    case VmOp.Blt:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (CompareLt(a, b, false)) pc = target;
                        break;
                    }
                    case VmOp.BltUn:
                    {
                        int target = ReadI32(code, ref pc);
                        VSlot b = stack[--sp]; VSlot a = stack[--sp];
                        if (CompareLt(a, b, true)) pc = target;
                        break;
                    }
                    case VmOp.Switch:
                    {
                        int count = ReadI32(code, ref pc);
                        uint idx = unchecked((uint)stack[--sp].AsI4());
                        int tableStart = pc;
                        pc += count * 4;
                        if (idx < (uint)count)
                        {
                            int target = BitConverter.ToInt32(code, tableStart + (int)idx * 4);
                            pc = target;
                        }
                        break;
                    }

                    case VmOp.LdFld:
                    {
                        int tok = ReadI32(code, ref pc);
                        FieldInfo f = ResolveField(tok);
                        object? inst = stack[--sp].ToUntypedObject();
                        stack[sp++] = VSlot.FromObject(f.GetValue(inst), f.FieldType);
                        break;
                    }
                    case VmOp.StFld:
                    {
                        int tok = ReadI32(code, ref pc);
                        FieldInfo f = ResolveField(tok);
                        object? val = stack[--sp].ToManagedObject(f.FieldType);
                        object? inst = stack[--sp].ToUntypedObject();
                        f.SetValue(inst, val);
                        break;
                    }
                    case VmOp.LdSFld:
                    {
                        int tok = ReadI32(code, ref pc);
                        FieldInfo f = ResolveField(tok);
                        stack[sp++] = VSlot.FromObject(f.GetValue(null), f.FieldType);
                        break;
                    }
                    case VmOp.StSFld:
                    {
                        int tok = ReadI32(code, ref pc);
                        FieldInfo f = ResolveField(tok);
                        object? val = stack[--sp].ToManagedObject(f.FieldType);
                        f.SetValue(null, val);
                        break;
                    }

                    case VmOp.Call:
                    case VmOp.CallVirt:
                    {
                        int tok = ReadI32(code, ref pc);
                        MethodBase m = ResolveMethod(tok);
                        ParameterInfo[] ps = m.GetParameters();
                        object?[] callArgs = new object?[ps.Length];
                        for (int i = ps.Length - 1; i >= 0; i--)
                        {
                            callArgs[i] = stack[--sp].ToManagedObject(ps[i].ParameterType);
                        }
                        object? targetObj = m.IsStatic ? null : stack[--sp].ToUntypedObject();

                        object? result = m.Invoke(targetObj, callArgs);
                        if (m is MethodInfo mi && mi.ReturnType != typeof(void))
                        {
                            stack[sp++] = VSlot.FromObject(result, mi.ReturnType);
                        }
                        break;
                    }

                    case VmOp.NewObj:
                    {
                        int tok = ReadI32(code, ref pc);
                        ConstructorInfo ci = (ConstructorInfo)ResolveMethod(tok);
                        ParameterInfo[] ps = ci.GetParameters();
                        object?[] callArgs = new object?[ps.Length];
                        for (int i = ps.Length - 1; i >= 0; i--)
                        {
                            callArgs[i] = stack[--sp].ToManagedObject(ps[i].ParameterType);
                        }
                        object inst = ci.Invoke(callArgs);
                        stack[sp++] = VSlot.FromObject(inst, ci.DeclaringType);
                        break;
                    }

                    case VmOp.CastClass:
                    {
                        int tok = ReadI32(code, ref pc);
                        Type t = ResolveType(tok);
                        object? val = stack[sp - 1].ToManagedObject(t);
                        if (val != null && !t.IsInstanceOfType(val))
                        {
                            throw new InvalidCastException();
                        }
                        stack[sp - 1] = VSlot.FromObject(val, t);
                        break;
                    }
                    case VmOp.IsInst:
                    {
                        int tok = ReadI32(code, ref pc);
                        Type t = ResolveType(tok);
                        object? val = stack[sp - 1].ToUntypedObject();
                        stack[sp - 1] = (val != null && t.IsInstanceOfType(val)) ? VSlot.FromObject(val, t) : VSlot.FromNull();
                        break;
                    }
                    case VmOp.Box:
                    {
                        int tok = ReadI32(code, ref pc);
                        Type t = ResolveType(tok);
                        object? val = stack[sp - 1].ToManagedObject(t);
                        stack[sp - 1] = new VSlot { Kind = val == null ? SlotKind.Null : SlotKind.Obj, Obj = val };
                        break;
                    }
                    case VmOp.UnboxAny:
                    {
                        int tok = ReadI32(code, ref pc);
                        Type t = ResolveType(tok);
                        object? val = stack[sp - 1].ToManagedObject(t);
                        stack[sp - 1] = VSlot.FromObject(val, t);
                        break;
                    }
                    case VmOp.NewArr:
                    {
                        int tok = ReadI32(code, ref pc);
                        Type elemType = ResolveType(tok);
                        int len = stack[--sp].AsI4();
                        Array arr = Array.CreateInstance(elemType, len);
                        stack[sp++] = new VSlot { Kind = SlotKind.Obj, Obj = arr };
                        break;
                    }
                    case VmOp.LdLen:
                    {
                        Array arr = (Array)stack[--sp].Obj!;
                        stack[sp++] = VSlot.FromI4(arr.Length);
                        break;
                    }
                    case VmOp.LdElem:
                    {
                        int tok = ReadI32(code, ref pc);
                        Type? elemType = tok >= 0 ? ResolveType(tok) : null;
                        int idx = stack[--sp].AsI4();
                        Array arr = (Array)stack[--sp].Obj!;
                        object? val = arr.GetValue(idx);
                        stack[sp++] = VSlot.FromObject(val, elemType ?? arr.GetType().GetElementType());
                        break;
                    }
                    case VmOp.StElem:
                    {
                        int tok = ReadI32(code, ref pc);
                        Type? elemType = tok >= 0 ? ResolveType(tok) : null;
                        VSlot valSlot = stack[--sp];
                        int idx = stack[--sp].AsI4();
                        Array arr = (Array)stack[--sp].Obj!;
                        Type et = elemType ?? arr.GetType().GetElementType()!;
                        arr.SetValue(valSlot.ToManagedObject(et), idx);
                        break;
                    }
                    case VmOp.LdToken:
                    {
                        byte kind = code[pc++];
                        int tok = ReadI32(code, ref pc);
                        if (kind == 0) stack[sp++] = new VSlot { Kind = SlotKind.Obj, Obj = ResolveType(tok).TypeHandle };
                        else if (kind == 1) stack[sp++] = new VSlot { Kind = SlotKind.Obj, Obj = ResolveField(tok).FieldHandle };
                        else stack[sp++] = new VSlot { Kind = SlotKind.Obj, Obj = ResolveMethod(tok).MethodHandle };
                        break;
                    }

                    case VmOp.Throw:
                    {
                        Exception? ex = stack[--sp].Obj as Exception;
                        throw (ex ?? new Exception());
                    }

                    case VmOp.Ret:
                    {
                        if (chunk.ReturnTypeSlot < 0)
                        {
                            return null;
                        }
                        Type retType = ResolveType(chunk.ReturnTypeSlot);
                        if (retType == typeof(void)) return null;
                        return sp > 0 ? stack[sp - 1].ToManagedObject(retType) : null;
                    }

                    default:
                        throw new InvalidProgramException();
                }
            }

            return null;
        }

        private static bool CompareEq(VSlot a, VSlot b)
        {
            if (a.Kind == SlotKind.Null || b.Kind == SlotKind.Null) return a.Kind == b.Kind || (a.Kind == SlotKind.I4 && a.I64 == 0 && b.Kind == SlotKind.Null) || (b.Kind == SlotKind.I4 && b.I64 == 0 && a.Kind == SlotKind.Null);
            if (a.Kind == SlotKind.Obj || b.Kind == SlotKind.Obj) return ReferenceEquals(a.ToUntypedObject(), b.ToUntypedObject()) || Equals(a.ToUntypedObject(), b.ToUntypedObject());
            if (a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 || b.Kind == SlotKind.R4 || b.Kind == SlotKind.R8) return a.AsR() == b.AsR();
            if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8) return a.AsI8() == b.AsI8();
            return a.AsI4() == b.AsI4();
        }

        private static bool CompareGt(VSlot a, VSlot b, bool unsigned)
        {
            if (a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 || b.Kind == SlotKind.R4 || b.Kind == SlotKind.R8) return a.AsR() > b.AsR();
            if (a.Kind == SlotKind.Obj || b.Kind == SlotKind.Obj) return a.ToUntypedObject() != null && b.ToUntypedObject() == null;
            if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8)
                return unsigned ? unchecked((ulong)a.AsI8()) > unchecked((ulong)b.AsI8()) : a.AsI8() > b.AsI8();
            return unsigned ? unchecked((uint)a.AsI4()) > unchecked((uint)b.AsI4()) : a.AsI4() > b.AsI4();
        }

        private static bool CompareLt(VSlot a, VSlot b, bool unsigned)
        {
            if (a.Kind == SlotKind.R4 || a.Kind == SlotKind.R8 || b.Kind == SlotKind.R4 || b.Kind == SlotKind.R8) return a.AsR() < b.AsR();
            if (a.Kind == SlotKind.I8 || b.Kind == SlotKind.I8)
                return unsigned ? unchecked((ulong)a.AsI8()) < unchecked((ulong)b.AsI8()) : a.AsI8() < b.AsI8();
            return unsigned ? unchecked((uint)a.AsI4()) < unchecked((uint)b.AsI4()) : a.AsI4() < b.AsI4();
        }

        private static int ReadU16(byte[] buf, ref int pc)
        {
            int v = buf[pc] | (buf[pc + 1] << 8);
            pc += 2;
            return v;
        }

        private static int ReadI32(byte[] buf, ref int pc)
        {
            int v = buf[pc] | (buf[pc + 1] << 8) | (buf[pc + 2] << 16) | (buf[pc + 3] << 24);
            pc += 4;
            return v;
        }

        private static long ReadI64(byte[] buf, ref int pc)
        {
            long lo = (uint)ReadI32(buf, ref pc);
            long hi = (uint)ReadI32(buf, ref pc);
            return lo | (hi << 32);
        }
    }
}
