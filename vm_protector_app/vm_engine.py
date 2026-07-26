import os
import random
import struct
import math
from typing import Dict, List, Tuple

class VMOpcode:
    """
    Sanal Makine Opcode Tanımları.
    Her koruma derlemesinde bu değerler rastgele karıştırılır (Opcode Shuffling).
    """
    def __init__(self):
        self.opcodes = {
            "MOV_REG_IMM": 0x10,
            "MOV_REG_REG": 0x20,
            "ADD_REG_REG": 0x30,
            "SUB_REG_REG": 0x35,
            "XOR_REG_IMM": 0x40,
            "XOR_REG_REG": 0x45,
            "PUSH_REG":    0x50,
            "POP_REG":     0x60,
            "JMP":         0x70,
            "JZ":          0x75,
            "PRINT_REG":   0x80,
            "EXEC_NATIVE": 0x90,
            "EXIT":        0xFF
        }
        self.shuffle_opcodes()

    def shuffle_opcodes(self):
        """Her koruma işleminde Opcode byte değerlerini rastgele yeniden haritalar."""
        used = set()
        for key in self.opcodes:
            if key == "EXIT":
                continue
            val = random.randint(0x01, 0xFE)
            while val in used or val == 0xFF:
                val = random.randint(0x01, 0xFE)
            used.add(val)
            self.opcodes[key] = val

class VMBytecodeEncoder:
    """
    Orijinal kod/byte akışlarını sanal opcode'lara dönüştüren ve şifreleyen derleyici.
    """
    def __init__(self, vm_opcodes: VMOpcode, xor_key: int = None):
        self.vm_opcodes = vm_opcodes.opcodes
        self.key = xor_key if xor_key is not None else random.randint(0x10, 0xFE)

    def encode_instruction(self, op_name: str, *args) -> bytes:
        stream = bytearray()
        op_code = self.vm_opcodes[op_name]
        stream.append(op_code)

        if op_name in ("MOV_REG_IMM", "XOR_REG_IMM"):
            reg, imm = args
            stream.append(reg & 0xFF)
            stream.extend(struct.pack("<Q", imm & 0xFFFFFFFFFFFFFFFF))
        elif op_name in ("MOV_REG_REG", "ADD_REG_REG", "SUB_REG_REG", "XOR_REG_REG"):
            dest_reg, src_reg = args
            stream.append(dest_reg & 0xFF)
            stream.append(src_reg & 0xFF)
        elif op_name in ("PUSH_REG", "POP_REG", "PRINT_REG"):
            reg = args[0]
            stream.append(reg & 0xFF)
        elif op_name == "JMP":
            target_pc = args[0]
            stream.extend(struct.pack("<I", target_pc & 0xFFFFFFFF))
        elif op_name == "EXEC_NATIVE":
            native_data = args[0]  # bytes
            stream.extend(struct.pack("<I", len(native_data)))
            stream.extend(native_data)
        elif op_name == "EXIT":
            pass

        return bytes(stream)

    def encrypt_bytecode(self, raw_bytecode: bytes) -> bytes:
        """Bytecode akışını dinamik key ile obfuscate / encrypt eder."""
        return bytes([b ^ self.key for b in raw_bytecode])
