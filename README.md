# Custom VMProtector

Windows PE dosyalarini sanal makine tabanli koruma ile sarmalayarak korumalı `.exe` ciktisi ureten bir yazilim koruma araci.

Hedef dosyanin makine kodunu ozel bir bytecode formatina cevirir, XOR ile sifreler ve gomulu bir VM yorumlayicisi ile calistirir. Tersine muhendislik ve statik analize karsi koruma saglar.

---

## Ozellikler

- Hedef binary'nin kod bolumunu ozel VM bytecode'una donusturur
- Her derlemede opcode degerleri rastgele yeniden atanir (Opcode Shuffling)
- Bytecode rastgele XOR anahtariyla sifrelenir
- pefile + capstone ile PE analizi (EntryPoint, .text section, x86/x64)
- Derleme sirasinda gercek zamanli ilerleme cubugu
- CustomTkinter tabanli koyu temali GUI

---

## Kullanim

### Hazir EXE
`VMProtector.exe` dosyasini indirip cift tiklayarak calistirin.

### Kaynak Koddan
```bash
pip install customtkinter pefile capstone pyinstaller
python vm_protector_app/main.py
```

---

## Dosya Yapisi

```
vm_protector_app/
  main.py              # Giris noktasi
  gui.py               # GUI arayuzu
  protector_core.py    # Koruma motoru (PE analizi + derleme)
  vm_engine.py         # Opcode tanimlari ve bytecode encoder
  vm_runtime_stub.py   # Korunan EXE'ye gomulen VM yorumlayici
```

---

## Koruma Akisi

```
Hedef .exe/.py -> PE Analizi -> Opcode Shuffling -> Bytecode Encode -> XOR Sifreleme -> VM Stub Uretimi -> PyInstaller Derleme -> Korumali .exe
```

---

## Gereksinimler

- Windows 10/11
- Python 3.10+
- customtkinter, pefile, capstone, PyInstaller

---

## Lisans

Egitim ve arastirma amaclidir. Kotuye kullanimdan kullanici sorumludur.
