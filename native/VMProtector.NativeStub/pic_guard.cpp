#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <cstdint>

// Pure Position-Independent x64 Native Guard compiled to standalone .text bytes
// Zero CRT, zero globals, zero static relocations, callable via VirtualAlloc(RX) from .NET 8!
extern "C" uint32_t __stdcall NativeGuardCheck(uint64_t challenge) noexcept {
    // Walk PEB directly via GS:[0x60]
    const uint8_t* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    uint32_t status = 0;

    if (!peb) {
        return 0xDEAD0001u;
    }

    // PEB->BeingDebugged at +0x02
    if (peb[2] != 0) {
        status |= 0x01u;
    }

    // PEB->NtGlobalFlag at +0xBC (Win64)
    const uint32_t ntGlobalFlag = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
    if ((ntGlobalFlag & 0x70u) != 0) {
        status |= 0x02u;
    }

    // Tight RDTSC single-step timing verification
    uint64_t t0 = __rdtsc();
    uint64_t acc = challenge ^ 0xA5A55A5A3C3CC3C3ULL;
    for (uint32_t i = 0; i < 32; ++i) {
        acc = ((acc << 7) | (acc >> 57)) ^ (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
        acc += 0xBF58476D1CE4E5B9ULL;
    }
    uint64_t t1 = __rdtsc();
    if ((t1 - t0) > 30000000ULL) {
        status |= 0x04u;
    }

    // Return masked cryptographic challenge proof when clean:
    // low 4 bits = debug flags (must be 0), upper 28 bits = expected challenge fold
    uint32_t proof = static_cast<uint32_t>((acc ^ (acc >> 32)) & 0xFFFFFFF0u);
    return proof | (status & 0x0Fu);
}
