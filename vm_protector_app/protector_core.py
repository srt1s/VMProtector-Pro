import os
import sys
import random
import subprocess
import shutil
import base64
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from vm_engine import VMOpcode, VMBytecodeEncoder

def find_system_python() -> str:
    """Derlenmiş frozen (EXE) ortamda bile gerçek python.exe yolunu bulur."""
    if not getattr(sys, 'frozen', False):
        return sys.executable

    candidates = [
        r"C:\Python314\python.exe",
        shutil.which("python.exe") or "",
        shutil.which("python") or "",
        r"C:\Python312\python.exe",
        r"C:\Python311\python.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Python\Python314\python.exe"),
        os.path.expanduser(r"~\AppData\Local\Programs\Python\Python312\python.exe"),
        os.path.expanduser(r"~\AppData\Local\Programs\Python\Python39\python.exe"),
    ]
    for cand in candidates:
        if cand and os.path.exists(cand) and not cand.lower().endswith("vmprotector.exe"):
            return cand
    return "python"

class VMProtectorCore:
    """
    Hedef dosyaları VMProtect mimarisiyle sanallaştırıp şifreleyen ve 
    çalıştırılabilir korumalı .exe dosyasına dönüştüren ana motor.
    """
    def __init__(self, anti_debug: bool = True, randomize_keys: bool = True):
        self.anti_debug = anti_debug
        self.randomize_keys = randomize_keys

    def protect_file(self, input_path: str, output_path: str = None, progress_callback=None) -> str:
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Girdi dosyası bulunamadı: {input_path}")

        if output_path is None:
            base, _ = os.path.splitext(input_path)
            output_path = f"{base}_vmp.exe"

        print(f"\n[VM PROTECTOR] Koruma Başlatılıyor: {os.path.basename(input_path)}")

        # 1. Opcode Haritası ve Şifreleme Anahtarını Üret
        vm_opcodes = VMOpcode()
        encoder = VMBytecodeEncoder(vm_opcodes)

        # 2. Hedef Dosya İçeriğini Analiz Et
        with open(input_path, "rb") as f:
            file_bytes = f.read()

        is_pe = file_bytes.startswith(b"MZ")
        raw_bytecode = bytearray()

        if is_pe:
            print(" -> Hedef Türü: PE Windows Binary (.exe / .dll)")
            try:
                pe = pefile.PE(data=file_bytes)
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                code_section = None
                for section in pe.sections:
                    if section.contains_rva(entry_point):
                        code_section = section
                        break
                
                if code_section:
                    print(f" -> EntryPoint Kodu Bölümü (.text): {code_section.Name.decode().strip(chr(0))}")
                    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32)
                    insns = list(md.disasm(code_section.get_data()[:1024], entry_point))
                    print(f" -> Capstone ile {len(insns)} x86/x64 komutu söküldü.")

            except Exception as e:
                print(f" -> PE Analiz Uyarısı: {e}")

            raw_bytecode.extend(encoder.encode_instruction("MOV_REG_IMM", 0, random.randint(1000, 9999)))
            raw_bytecode.extend(encoder.encode_instruction("XOR_REG_IMM", 0, 0xABCDEF))
            raw_bytecode.extend(encoder.encode_instruction("EXEC_NATIVE", file_bytes))
            raw_bytecode.extend(encoder.encode_instruction("EXIT"))

        else:
            print(" -> Hedef Türü: Betik / İkili Veri (Script / Binary Payload)")
            raw_bytecode.extend(encoder.encode_instruction("MOV_REG_IMM", 0, 100))
            raw_bytecode.extend(encoder.encode_instruction("EXEC_NATIVE", file_bytes))
            raw_bytecode.extend(encoder.encode_instruction("EXIT"))

        # 3. Bytecode'u Şifrele (XOR Obfuscation)
        encrypted_bytecode = encoder.encrypt_bytecode(bytes(raw_bytecode))

        # 4. Gömülü Standalone Runner Script'ini Oluştur
        build_dir = os.path.join(os.path.dirname(os.path.abspath(input_path)), "_vmp_build_tmp")
        os.makedirs(build_dir, exist_ok=True)
        runner_script = os.path.join(build_dir, "vmp_loader.py")

        b64_bytecode = base64.b64encode(encrypted_bytecode).decode('ascii')
        opcodes_map_repr = repr(vm_opcodes.opcodes)
        key_val = encoder.key

        loader_code = f'''import base64
import sys
import os
import struct
import ctypes

# VMPROTECTED STANDALONE RUNNER
ANTI_DEBUG = {self.anti_debug}
KEY = {key_val}
OPCODES = {opcodes_map_repr}
B64_BYTECODE = "{b64_bytecode}"

def check_anti_debug():
    if not ANTI_DEBUG:
        return
    try:
        if sys.platform == "win32":
            if ctypes.windll.kernel32.IsDebuggerPresent() != 0:
                print("[SECURITY ALERT] Debugger Detected! Exiting.")
                sys.exit(0)
    except Exception:
        pass

class VMInterpreter:
    def __init__(self, raw_bytecode):
        self.raw = raw_bytecode
        self.opcodes_map = {{v: k for k, v in OPCODES.items()}}
        self.v_regs = [0] * 8
        self.v_pc = 0
        self.running = True

    def run(self):
        check_anti_debug()
        decrypted = bytes([b ^ KEY for b in self.raw])
        while self.running and self.v_pc < len(decrypted):
            op = decrypted[self.v_pc]
            self.v_pc += 1
            op_name = self.opcodes_map.get(op, "UNKNOWN")

            if op_name == "MOV_REG_IMM":
                reg = decrypted[self.v_pc]
                self.v_pc += 1
                imm = struct.unpack("<Q", decrypted[self.v_pc:self.v_pc+8])[0]
                self.v_pc += 8
                self.v_regs[reg] = imm
            elif op_name == "XOR_REG_IMM":
                reg = decrypted[self.v_pc]
                self.v_pc += 1
                imm = struct.unpack("<Q", decrypted[self.v_pc:self.v_pc+8])[0]
                self.v_pc += 8
                self.v_regs[reg] ^= imm
            elif op_name == "EXEC_NATIVE":
                length = struct.unpack("<I", decrypted[self.v_pc:self.v_pc+4])[0]
                self.v_pc += 4
                payload = decrypted[self.v_pc:self.v_pc+length]
                self.v_pc += length
                
                # PE Executable veya Script Çalıştırma
                if payload.startswith(b"MZ"):
                    tmp_exe = os.path.join(os.environ.get("TEMP", "."), "_vmp_payload.exe")
                    with open(tmp_exe, "wb") as f:
                        f.write(payload)
                    try:
                        import subprocess
                        p = subprocess.run([tmp_exe] + sys.argv[1:], check=False)
                    finally:
                        if os.path.exists(tmp_exe):
                            try:
                                os.remove(tmp_exe)
                            except Exception:
                                pass
                else:
                    exec_scope = {{}}
                    exec(payload.decode('utf-8', errors='ignore'), exec_scope)

            elif op_name == "EXIT":
                self.running = False

if __name__ == "__main__":
    raw_bc = base64.b64decode(B64_BYTECODE)
    vm = VMInterpreter(raw_bc)
    vm.run()
'''
        with open(runner_script, "w", encoding="utf-8") as f:
            f.write(loader_code)

        print(f" -> VM Stub Loader Üretildi: {runner_script}")
        print(" -> PyInstaller ile Derleme Başlatılıyor (EXE Üretiliyor)...")

        # 5. PyInstaller ile EXE'ye derle
        python_bin = find_system_python()
        print(f" -> Kullanılan Python Yolu: {python_bin}")

        cmd = [
            python_bin, "-m", "PyInstaller",
            "--noconfirm",
            "--onefile",
            "--console",
            "--distpath", os.path.dirname(output_path),
            "--name", os.path.splitext(os.path.basename(output_path))[0],
            "--workpath", os.path.join(build_dir, "work"),
            "--specpath", build_dir,
            runner_script
        ]

        # Gerçek zamanlı çıktı takibi için Popen kullanımı
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        res_stdout = []
        for line in process.stdout:
            res_stdout.append(line)
            # Analiz çıktılarından ilerleme durumunu saptayalım
            progress_val = 0.0
            if "checking Analysis" in line:
                progress_val = 0.15
            elif "Running Analysis" in line:
                progress_val = 0.30
            elif "Caching module dependency graph" in line:
                progress_val = 0.50
            elif "Analyzing" in line:
                progress_val = 0.65
            elif "Building PYZ" in line:
                progress_val = 0.75
            elif "Building PKG" in line:
                progress_val = 0.85
            elif "Building EXE" in line:
                progress_val = 0.95
            elif "Build complete" in line:
                progress_val = 1.00

            if progress_callback and progress_val > 0.0:
                progress_callback(progress_val)

        process.wait()
        exit_code = process.returncode
        res_stdout_str = "".join(res_stdout)
        
        # Geçici build klasörünü temizle
        if os.path.exists(build_dir):
            try:
                shutil.rmtree(build_dir)
            except Exception:
                pass

        if os.path.exists(output_path) and exit_code == 0:
            if progress_callback:
                progress_callback(1.0)
            print(f"\n[SUCCESS] VM Korumalı EXE Başarıyla Oluşturuldu: {output_path}")
            return output_path
        else:
            error_msg = (
                f"[ERR-COMP-501] PyInstaller Derleme Hatası (Exit Code: {exit_code})\n"
                f"--- STDOUT ---\n{res_stdout_str[-2000:] if res_stdout_str else 'Yok'}"
            )
            print(f"[ERROR] {error_msg}")
            raise RuntimeError(error_msg)
