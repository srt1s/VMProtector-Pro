import sys
import os
import argparse

# Mevcut dizini sys.path'e ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protector_core import VMProtectorCore
from gui import VMProtectorGUI

def main():
    parser = argparse.ArgumentParser(description="VMProtector - Sanal Makine Bazlı Kod Koruyucu")
    parser.add_argument("-f", "--file", type=str, help="VM-Protect ile korunacak hedef dosya yolu")
    parser.add_argument("-o", "--output", type=str, help="Üretilecek korumalı .exe dosyasının çıkış yolu")
    parser.add_argument("--no-antidebug", action="store_true", help="Anti-Debugging korumasını devre dışı bırakır")
    
    args = parser.parse_args()

    if args.file:
        # CLI Modu
        print("=== VMPROTECTOR CLI MODU ===")
        try:
            protector = VMProtectorCore(anti_debug=not args.no_antidebug)
            out_file = protector.protect_file(args.file, args.output)
            print(f"\n[+] İşlem Tamamlandı. Korumalı EXE: {out_file}")
        except Exception as e:
            print(f"\n[-] Hata: {e}")
            sys.exit(1)
    else:
        # GUI Modu
        app = VMProtectorGUI()
        app.mainloop()

if __name__ == "__main__":
    main()
