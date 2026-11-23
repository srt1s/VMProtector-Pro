#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include "crypto.hpp"
#include "peb_api.hpp"

namespace vmp::antidebug {

using FnNtQueryInformationProcess = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using FnGetCurrentThread          = HANDLE(WINAPI*)();
using FnGetThreadContext          = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
using FnCheckRemoteDebugger       = BOOL(WINAPI*)(HANDLE, PBOOL);
using FnGetCurrentProcess         = HANDLE(WINAPI*)();

inline uint32_t probe_environment_flags() noexcept {
    uint32_t flags = 0;

    // 1. Direct PEB->BeingDebugged + PEB->NtGlobalFlag (0x70 = heap debug flags)
    auto* p = peb::get_peb();
    if (p) {
        if (p->BeingDebugged != 0) {
            flags |= 0x01u;
        }
        if ((p->NtGlobalFlag & 0x70u) != 0) {
            flags |= 0x02u;
        }
    }

    // 2. NtQueryInformationProcess (DebugPort=7, DebugObjectHandle=0x1E, DebugFlags=0x1F)
    auto ntQuery = peb::resolve<FnNtQueryInformationProcess>(
        peb::HASH_NTDLL, crypto::fnv1a64("NtQueryInformationProcess"));
    auto getCurProc = peb::resolve<FnGetCurrentProcess>(
        peb::HASH_KERNEL32, crypto::fnv1a64("GetCurrentProcess"));

    if (ntQuery && getCurProc) {
        HANDLE hProc = getCurProc();
        ULONG_PTR debugPort = 0;
        if (ntQuery(hProc, 7, &debugPort, sizeof(debugPort), nullptr) == 0 && debugPort != 0) {
            flags |= 0x04u;
        }
        HANDLE debugObj = nullptr;
        if (ntQuery(hProc, 0x1E, &debugObj, sizeof(debugObj), nullptr) == 0 && debugObj != nullptr) {
            flags |= 0x08u;
        }
        ULONG debugFlags = 1;
        if (ntQuery(hProc, 0x1F, &debugFlags, sizeof(debugFlags), nullptr) == 0 && debugFlags == 0) {
            flags |= 0x10u;
        }
    }

    // 3. Hardware Breakpoints (Dr0..Dr3)
    auto getCurThread = peb::resolve<FnGetCurrentThread>(
        peb::HASH_KERNEL32, crypto::fnv1a64("GetCurrentThread"));
    auto getThreadCtx = peb::resolve<FnGetThreadContext>(
        peb::HASH_KERNEL32, crypto::fnv1a64("GetThreadContext"));
    if (getCurThread && getThreadCtx) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (getThreadCtx(getCurThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                flags |= 0x20u;
            }
        }
    }

    // 4. RDTSC single-step anomaly check
    uint64_t t0 = __rdtsc();
    volatile uint64_t mix = 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 64; ++i) {
        mix = crypto::rotl64(mix ^ static_cast<uint64_t>(i), 7) + 0xBF58476D1CE4E5B9ULL;
    }
    uint64_t t1 = __rdtsc();
    (void)mix;
    if ((t1 - t0) > 25000000ULL) {
        flags |= 0x40u;
    }

    return flags;
}

} // namespace vmp::antidebug
