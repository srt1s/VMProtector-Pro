# VMProtector-Pro v2.0

**.NET 8 SingleFile, .NET Assembly (WPF/WinForms/Console) & Native PE64 (x64) Software Protection Suite** — built from scratch in **C# (.NET 8 + AsmResolver)** and **C++20 (x64)**.

Designed specifically for production applications like **ToprakExternal** (`PublishSingleFile` + WPF + Direct3D11/ImGui.NET + embedded licensing) as well as native Windows x64 PE binaries, **without dropping plaintext executables to `%TEMP%`**.

---

## Mimari & Koruma Katmanları

### 1. .NET 8 / Managed Koruma Motoru (`VMProtector.Core` + `VMProtector.Runtime`)
* **MSIL -> Polymorphic Stack VM Sanallaştırma (`MethodVirtualizerPass`):**
  * Uygun metodların orijinal MSIL opcode'larını çıkarır ve her build'de **rastgele karıştırılmış 256-entry opcode tablosuna** sahip özel VM bytecode'una çevirir.
  * Orijinal metod gövdeleri silinip yerine yalnızca VM yorumlayıcı köprüsü (`VmEngine.Run`) bırakılır.
  * `OpCodes.Ldtoken` tabanlı `TokenTable` ile yeniden adlandırma ve PE rebuilding sonrası bile tüm tip/metod/alan token'ları tutarlı kalır.
* **ChaCha20 String & Secret Vault (`StringEncryptionPass`):**
  * Tüm `ldstr` sabitlerini RFC 8439 **ChaCha20** ile şifreleyip private manifest resource içine gizler; anahtar/nonce getter'ları poliformik XOR aritmetiğiyle ilmeklenir. `strings.exe` / AI statik analizi düz metin bulamaz.
* **Control Flow Flattening + Opaque Predicates (`ControlFlowPass`):**
  * Basic block'ları ayırır, fiziksel sırayı karıştırır, XOR maskeli `switch` state machine ve matematiksel opaque predicate dalları ekler.
* **Numeric Constant Mutation (`ConstantMutationPass`):**
  * Sabit tamsayı yüklemelerini (`ldc.i4`) çok adımlı XOR/ADD/SUB kimliklerine parçalar.
* **Akıllı WPF/BAML Güvenli İsim Gizleme (`RenamingPass`):**
  * `*.g.resources` / BAML akışlarını otomatik tarayarak XAML sınıflarını, `x:Name` bağlamalarını ve özel öznitelikleri (`[Obfuscation]`, `AssemblyMetadata`) bozmadan iç tip/metot/alanları gizler ve parametre isimlerini temizler.
* **Native x64 PIC Shellcode + Anti-Debug (`SecurityGuard`):**
  * `<Module>::.cctor` içerisinden çalıştırılır.
  * Diske `.dll` bırakmadan bellek içinde `VirtualAlloc(RW)` -> `VirtualProtect(RX)` W^X izniyle **MSVC C++20 ile derlenmiş 225 byte Position-Independent x64 machine code (`pic_guard.cpp`)** yürütür (`PEB->BeingDebugged`, `PEB->NtGlobalFlag`, `__rdtsc()` stepping kontrolü + kriptografik challenge proof).
  * `NtQueryInformationProcess` (`DebugPort`, `DebugObjectHandle`, `DebugFlags`), `CheckRemoteDebuggerPresent` ve opsiyonel RE araç taraması (`dnSpy`, `ILSpy`, `x64dbg`, `IDA`, `OllyDbg`, `Cheat Engine`) içerir.
* **.NET 8 SingleFile Stage-2 In-Memory Bootstrapper (`SingleFileStage2Builder`):**
  * `.NET 8 PublishSingleFile` paketlerini otomatik ayrıştırır (`BundleManifest`).
  * Korunan giriş assembly'sini sıkıştırıp **ChaCha20 + CRC32** ile şifreler; bundle içine yalnızca bellekten `Assembly.Load` + `Application.ResourceAssembly` senkronizasyonu yapan minimal bir loader koyar (`singlefileextractor` / `ILSpy` doğrudan hedef DLL'i çıkaramaz).

### 2. Native x64 PE Koruma Motoru (`native/VMProtector.NativeStub`)
* **C++20 Polymorphic Key VM + ChaCha20 + Reflective In-Memory PE64 Loader:**
  * Dışarıdan static `VirtualAlloc` / `VirtualProtect` import'u olmadan `PEB->Ldr` üzerinden **FNV-1a API hashing** ile Win32 API'lerini çözer.
  * ChaCha20 çözümleme anahtarını düz halde saklamaz; çalışma anında **her build'de değişen opcode tablosuna sahip C++20 sanal makinesi** VM register'ları içinde anahtarı türetir ve `PEB` / `NtGlobalFlag` / `Dr0-Dr3` / `__rdtsc()` debugger tespitinde anahtarı sessizce bozar.
  * Hedef PE64'ü `.vmpx` section'ından **tamamen RAM üzerinde** map eder (relocations, IAT, section W^X permissions, `RtlAddFunctionTable` SEH/C++ exceptions, `PEB->ImageBaseAddress`, TLS callbacks) ve diske sıfır geçici dosya bırakır.

---

## Proje Yapısı

```text
native/VMProtector.NativeStub/   # C++20 x64 Native VM, ChaCha20, Anti-Debug, PE64 RAM Loader & PIC Guard
src/VMProtector.Runtime/         # Hedef .NET assembly içine gömülen sanal makine & ChaCha20 vault runtime
src/VMProtector.Core/            # AsmResolver.DotNet tabanlı koruma pipeline'ı ve 7 koruma katmanı
src/VMProtector.CLI/             # Komut satırı aracı (vmp-cli.exe)
src/VMProtector.GUI/             # Koyu temalı WPF masaüstü arayüzü (VMProtector.exe)
tests/VMProtector.Tests/         # Otomatik .NET DLL, SingleFile Stage-2 ve Native PE64 doğrulama paketi
build.ps1                        # Tek komutla C++20 + .NET 8 derleme, test ve publish betiği
```

---

## Kurulum & Kullanım

### Gereksinimler
* Windows 10/11 x64
* [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
* Visual Studio 2022/2026 C++ x64 Araç Takımı (`cl.exe`) + Python 3 (yalnızca `pic_guard.obj` çıkarmak için)

### Tek Komutla Derle & Test Et
```powershell
.\build.ps1
```
Çıktılar `release\` klasöründe (`VMProtector.exe` ve `vmp-cli.exe`) ve kök dizinde üretilir.

### CLI Kullanımı
```powershell
# Hedef binary analizi (PE bölümleri, Shannon entropisi, VM uyumlu metot sayısı)
.\vmp-cli.exe inspect ToprakExternal_Client.exe

# ToprakExternal Maximum profiliyle koruma (.NET 8 SingleFile Stage-2 + VM + ChaCha20)
.\vmp-cli.exe protect ToprakExternal_Client.exe -o ToprakExternal_Client_vmp.exe --preset toprak

# Native x64 C/C++ EXE koruma
.\vmp-cli.exe protect MyNativeApp.exe -o MyNativeApp_vmp.exe --preset native
```

### GUI Kullanımı
`VMProtector.exe` uygulamasını açıp `.exe` veya `.dll` dosyasını pencereye sürükleyip bırakın, profil seçin ve **KORUMAYI BAŞLAT** butonuna basın.
