#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include "crypto.hpp"
#include "peb_api.hpp"
#include "vm_engine.hpp"
#include "pe_loader.hpp"

namespace {

bool find_vmpx_section(const uint8_t* modBase, const uint8_t*& outPtr, size_t& outSize) noexcept {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(modBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(modBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_SECTION_HEADER* secs = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(secs[i].Name, ".vmpx", 5) == 0) {
            outPtr = modBase + secs[i].VirtualAddress;
            outSize = secs[i].Misc.VirtualSize ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
            return true;
        }
    }
    return false;
}

int run_stub() {
    auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    const uint8_t* secPtr = nullptr;
    size_t secSize = 0;

    if (!find_vmpx_section(base, secPtr, secSize)) {
        return 0;
    }

    if (secSize < sizeof(vmp::vm::VmpSectionBundleHeader)) {
        return -2;
    }

    vmp::vm::VmpSectionBundleHeader hdr{};
    std::memcpy(&hdr, secPtr, sizeof(hdr));
    if (hdr.magic != 0x58504D56u) { // "VMPX"
        return -3;
    }

    const size_t needed = sizeof(hdr) + hdr.vmBytecodeLen + hdr.payloadRawLen;
    if (secSize < needed || hdr.payloadRawLen == 0) {
        return -4;
    }

    const uint8_t* encVmCode  = secPtr + sizeof(hdr);
    const uint8_t* encPayload = encVmCode + hdr.vmBytecodeLen;

    uint8_t derivedKey[32]{};
    const bool antiDebug = (hdr.flags & 0x01u) != 0;
    if (!vmp::vm::execute_key_vm(hdr, encVmCode, derivedKey, antiDebug)) {
        return -5;
    }

    std::vector<uint8_t> decrypted(hdr.payloadRawLen);
    vmp::crypto::chacha20_xor(derivedKey, hdr.nonce, 1u, encPayload, decrypted.data(), decrypted.size());

    volatile uint8_t* kp = derivedKey;
    for (size_t i = 0; i < sizeof(derivedKey); ++i) kp[i] = 0;

    if (vmp::crypto::crc32_ieee(decrypted.data(), decrypted.size()) != hdr.payloadCrc) {
        // Tamper or debugger corrupted the derived key silently -> abort cleanly
        return -6;
    }

    return vmp::loader::execute_pe64_in_memory(decrypted.data(), decrypted.size());
}

} // namespace

#ifdef VMP_GUI_SUBSYSTEM
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    return run_stub();
}
#else
int main() {
    return run_stub();
}
#endif
