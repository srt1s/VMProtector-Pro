# 🛡️ VMProtector Pro

**Windows hedef dosyalarını sanal makine tabanlı koruma ile sanallaştırarak korumalı `.exe` dosyasına dönüştüren gelişmiş bir yazılım koruma aracı.**

VMProtector Pro, hedef dosyanızın makine kodunu (x86/x64) kendi özel sanal makine mimarisine çevirerek, tersine mühendislik (reverse engineering) ve statik analiz girişimlerine karşı güçlü bir koruma katmanı sağlar.

---

## ⚡ Özellikler

- **VM Sanallaştırma** — Hedef binary'nin kod bölümünü (.text) özel bir bytecode formatına dönüştürür ve gömülü bir sanal makine yorumlayıcısı (interpreter) ile çalıştırır.
- **Opcode Shuffling** — Her derleme işleminde sanal makine opcode değerleri rastgele yeniden atanır. Aynı dosya iki kez korunsa bile üretilen bytecode tamamen farklı olur.
- **XOR Şifreleme** — Üretilen bytecode, rastgele üretilen bir XOR anahtarıyla şifrelenir. Statik analiz araçları ham bytecode'u okuyamaz.
- **PE Analizi** — `pefile` ve `capstone` kütüphaneleri ile hedef dosyanın EntryPoint'i, kod bölümü ve x86/x64 komut seti otomatik olarak analiz edilir.
- **Anti-Debug Desteği** — Koruma katmanında hata ayıklayıcı (debugger) algılama mekanizması.
- **Gerçek Zamanlı İlerleme Çubuğu** — Derleme süreci boyunca PyInstaller çıktısı gerçek zamanlı takip edilir ve ilerleme çubuğu sahte değil, gerçek aşamalara göre güncellenir.
- **Modern GUI** — CustomTkinter tabanlı, koyu temalı ve kullanımı kolay masaüstü arayüzü.

---

## 📸 Ekran Görüntüsü

> Uygulama açıldığında karşınıza çıkan ana ekran:

```
┌─────────────────────────────────────────────────────┐
│  🛡️ VM PROTECTOR PRO                                │
│                                                     │
│  [Dosya Seç]  C:\hedef\program.exe                  │
│                                                     │
│  ☑ Anti-Debug Koruması                              │
│  ☑ Opcode Randomization                             │
│                                                     │
│  [████████████████████░░░░] %85 - Building EXE...   │
│                                                     │
│  ⚡ DOSYAYI KORU VE DERLE (.EXE)                    │
│                                                     │
│  Log:                                               │
│  > İşlem Başlatıldı: program.exe                    │
│  > Hedef Türü: PE Windows Binary                    │
│  > ✅ Tamamlandı: program_protected.exe             │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Kullanım

### Hazır EXE ile (Kurulum Gerektirmez)
`VMProtector.exe` dosyasını indirip çift tıklayarak doğrudan çalıştırabilirsiniz.

### Kaynak Koddan Çalıştırma
```bash
# Gerekli kütüphaneleri yükleyin
pip install customtkinter pefile capstone pyinstaller

# Uygulamayı başlatın
python vm_protector_app/main.py
```

### Komut Satırından Derleme
```bash
python -m PyInstaller --noconfirm --onefile --windowed ^
  --name VMProtector ^
  --add-data "vm_protector_app;vm_protector_app" ^
  vm_protector_app/main.py
```

---

## 🏗️ Mimari

```
vm_protector_app/
├── main.py              # Uygulama giriş noktası
├── gui.py               # CustomTkinter GUI arayüzü
├── protector_core.py    # Koruma motoru (PE analizi + derleme)
├── vm_engine.py         # Sanal makine opcode tanımları ve bytecode encoder
└── vm_runtime_stub.py   # Korunan EXE'ye gömülen VM yorumlayıcı kodu
```

### Koruma Akışı

```
Hedef .exe / .py
       │
       ▼
  PE Analizi (pefile + capstone)
       │
       ▼
  Opcode Shuffling (rastgele opcode haritası)
       │
       ▼
  Bytecode Encode (özel VM instruction set)
       │
       ▼
  XOR Şifreleme (rastgele anahtar)
       │
       ▼
  VM Stub Loader Üretimi (gömülü interpreter)
       │
       ▼
  PyInstaller ile .exe Derleme
       │
       ▼
  Korumalı .exe Çıktısı ✅
```

---

## ⚙️ Gereksinimler

| Bileşen | Minimum Versiyon |
|---|---|
| İşletim Sistemi | Windows 10 / 11 |
| Python | 3.10+ |
| customtkinter | 5.x |
| pefile | 2023.x+ |
| capstone | 5.x |
| PyInstaller | 6.x |

---

## 📄 Lisans

Bu proje eğitim ve araştırma amaçlıdır. Kötüye kullanımdan kullanıcı sorumludur.

---

**Geliştirici:** [trikoliban](https://github.com/trikoliban)
