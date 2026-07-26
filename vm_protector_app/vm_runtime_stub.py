import sys
import os
import struct
import time
import ctypes

def check_anti_debug():
    """Çalışma zamanı Anti-Debugging ve Anti-Analysis kontrolleri."""
    try:
        if sys.platform == "win32":
            # 1. Windows API IsDebuggerPresent Kontrolü
            if ctypes.windll.kernel32.IsDebuggerPresent() != 0:
                print("[SECURITY ALERT] Hata Ayıklayıcı (Debugger) Tespit Edildi! İşlem Sonlandırılıyor.")
                sys.exit(0)
            
            # 2. RemoteDebuggerPresent Kontrolü
            is_remote = ctypes.c_bool(False)
            ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
                ctypes.windll.kernel32.GetCurrentProcess(), 
                ctypes.byref(is_remote)
            )
            if is_remote.value:
                print("[SECURITY ALERT] Uzaktan Hata Ayıklayıcı Tespit Edildi!")
                sys.exit(0)
    except Exception:
        pass

class VMInterpreterRuntime:
    """
    Sanal Makine Çalıştırıcı Stub (Interpreter Core).
    Korumalı dosyaların içinde yer alan ve sanal koda hayat veren motor.
    """
    def __init__(self, bytecode: bytes, key: int, opcodes_map: dict):
        self.raw_bytecode = bytecode
        self.key = key
        self.opcodes_map = {v: k for k, v in opcodes_map.items()} # Reverse map
        self.v_regs = [0] * 8
        self.v_stack = []
        self.v_pc = 0
        self.running = True

    def run(self):
        check_anti_debug()

        # Bytecode Şifresini Çöz
        decrypted = bytes([b ^ self.key for b in self.raw_bytecode])
        
        while self.running and self.v_pc < len(decrypted):
            opcode_val = decrypted[self.v_pc]
            self.v_pc += 1

            op_name = self.opcodes_map.get(opcode_val, "UNKNOWN")

            if op_name == "MOV_REG_IMM":
                reg = decrypted[self.v_pc]
                self.v_pc += 1
                imm = struct.unpack("<Q", decrypted[self.v_pc:self.v_pc+8])[0]
                self.v_pc += 8
                self.v_regs[reg] = imm

            elif op_name == "MOV_REG_REG":
                dest_reg = decrypted[self.v_pc]
                src_reg = decrypted[self.v_pc+1]
                self.v_pc += 2
                self.v_regs[dest_reg] = self.v_regs[src_reg]

            elif op_name == "ADD_REG_REG":
                dest_reg = decrypted[self.v_pc]
                src_reg = decrypted[self.v_pc+1]
                self.v_pc += 2
                self.v_regs[dest_reg] = (self.v_regs[dest_reg] + self.v_regs[src_reg]) & 0xFFFFFFFFFFFFFFFF

            elif op_name == "SUB_REG_REG":
                dest_reg = decrypted[self.v_pc]
                src_reg = decrypted[self.v_pc+1]
                self.v_pc += 2
                self.v_regs[dest_reg] = (self.v_regs[dest_reg] - self.v_regs[src_reg]) & 0xFFFFFFFFFFFFFFFF

            elif op_name == "XOR_REG_IMM":
                reg = decrypted[self.v_pc]
                self.v_pc += 1
                imm = struct.unpack("<Q", decrypted[self.v_pc:self.v_pc+8])[0]
                self.v_pc += 8
                self.v_regs[reg] ^= imm

            elif op_name == "PUSH_REG":
                reg = decrypted[self.v_pc]
                self.v_pc += 1
                self.v_stack.append(self.v_regs[reg])

            elif op_name == "POP_REG":
                reg = decrypted[self.v_pc]
                self.v_pc += 1
                if self.v_stack:
                    self.v_regs[reg] = self.v_stack.pop()

            elif op_name == "PRINT_REG":
                reg = decrypted[self.v_pc]
                self.v_pc += 1
                print(f"[VM OUTPUT] Sanal Yazmaç vR{reg} Değeri: {self.v_regs[reg]} (0x{self.v_regs[reg]:X})")

            elif op_name == "EXEC_NATIVE":
                length = struct.unpack("<I", decrypted[self.v_pc:self.v_pc+4])[0]
                self.v_pc += 4
                native_payload = decrypted[self.v_pc:self.v_pc+length]
                self.v_pc += length
                
                # Sanal alandan çıkarak korunan native yükü/kodu çalıştır
                try:
                    exec_scope = {}
                    exec(native_payload.decode('utf-8', errors='ignore'), exec_scope)
                except Exception as e:
                    print(f"[VM NATIVE EXEC ERROR] {e}")

            elif op_name == "EXIT":
                self.running = False

            else:
                print(f"[VM ERROR] Geçersiz veya Bozunmuş Opcode: 0x{opcode_val:X}")
                self.running = False
