# Custom VMProtector

Windows PE dosyalarını sanal makine tabanlı koruma ile sarmalayarak korumalı `.exe` çıktısı üreten bir yazılım koruma aracı.

Hedef dosyanın makine kodunu özel bir bytecode formatına çevirir, XOR ile şifreler ve gömülü bir VM yorumlayıcısı ile çalıştırır. Tersine mühendislik ve statik analize karşı koruma sağlar.

---

## Özellikler

- Hedef binary'nin kod bölümünü özel VM bytecode'una dönüştürür
- Her derlemede opcode değerleri rastgele yeniden atanır (Opcode Shuffling)
- Bytecode rastgele XOR anahtarıyla şifrelenir
- pefile + capstone ile PE analizi (EntryPoint, .text section, x86/x64)
- Derleme sırasında gerçek zamanlı ilerleme çubuğu
- CustomTkinter tabanlı koyu temalı GUI

---

## Kullanım

### Hazır EXE
`VMProtector.exe` dosyasını indirip çift tıklayarak çalıştırın.

### Kaynak Koddan
```bash
pip install customtkinter pefile capstone pyinstaller
python vm_protector_app/main.py
```

---

## Dosya Yapısı

```
vm_protector_app/
  main.py              # Giriş noktası
  gui.py               # GUI arayüzü
  protector_core.py    # Koruma motoru (PE analizi + derleme)
  vm_engine.py         # Opcode tanımları ve bytecode encoder
  vm_runtime_stub.py   # Korunan EXE'ye gömülen VM yorumlayıcı
```

---

## Koruma Akışı

```
Hedef .exe/.py -> PE Analizi -> Opcode Shuffling -> Bytecode Encode -> XOR Şifreleme -> VM Stub Üretimi -> PyInstaller Derleme -> Korumalı .exe
```

---

## Gereksinimler

- Windows 10/11
- Python 3.10+
- customtkinter, pefile, capstone, PyInstaller

---

## Lisans

Eğitim ve araştırma amaçlıdır. Kötüye kullanımdan kullanıcı sorumludur.
