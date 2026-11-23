#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "crypto.hpp"
#include "peb_api.hpp"

namespace vmp::loader {

using FnVirtualAlloc        = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using FnVirtualProtect      = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using FnVirtualFree         = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);
using FnLoadLibraryA        = HMODULE(WINAPI*)(LPCSTR);
using FnGetProcAddress      = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using FnFlushInstruction    = BOOL(WINAPI*)(HANDLE, LPCVOID, SIZE_T);
using FnGetCurrentProcess   = HANDLE(WINAPI*)();
using FnRtlAddFunctionTable = BOOLEAN(NTAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
using FnExeEntry            = int(WINAPI*)();
using FnDllEntry            = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

struct ImageRelocBlock {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

inline DWORD section_characteristics_to_protect(DWORD ch) noexcept {
    bool exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool read  = (ch & IMAGE_SCN_MEM_READ) != 0;
    bool write = (ch & IMAGE_SCN_MEM_WRITE) != 0;

    if (exec) {
        if (write) return PAGE_EXECUTE_READWRITE;
        if (read)  return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (write) return PAGE_READWRITE;
    if (read)  return PAGE_READONLY;
    return PAGE_NOACCESS;
}

inline int execute_pe64_in_memory(const uint8_t* rawPe, size_t rawSize) noexcept {
    if (!rawPe || rawSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
        return -10;
    }

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawPe);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -11;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > rawSize) return -12;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(rawPe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -13;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return -14;

    auto fnVirtualAlloc = peb::resolve<FnVirtualAlloc>(peb::HASH_KERNEL32, crypto::fnv1a64("VirtualAlloc"));
    auto fnVirtualProtect = peb::resolve<FnVirtualProtect>(peb::HASH_KERNEL32, crypto::fnv1a64("VirtualProtect"));
    auto fnLoadLibraryA = peb::resolve<FnLoadLibraryA>(peb::HASH_KERNEL32, crypto::fnv1a64("LoadLibraryA"));
    auto fnGetProcAddress = peb::resolve<FnGetProcAddress>(peb::HASH_KERNEL32, crypto::fnv1a64("GetProcAddress"));
    auto fnFlushICache = peb::resolve<FnFlushInstruction>(peb::HASH_KERNEL32, crypto::fnv1a64("FlushInstructionCache"));
    auto fnGetCurProc = peb::resolve<FnGetCurrentProcess>(peb::HASH_KERNEL32, crypto::fnv1a64("GetCurrentProcess"));
    auto fnRtlAddFunc = peb::resolve<FnRtlAddFunctionTable>(peb::HASH_KERNEL32, crypto::fnv1a64("RtlAddFunctionTable"));

    if (!fnVirtualAlloc || !fnVirtualProtect || !fnLoadLibraryA || !fnGetProcAddress) {
        return -15;
    }

    const uint64_t preferredBase = nt->OptionalHeader.ImageBase;
    const size_t imageSize = nt->OptionalHeader.SizeOfImage;

    uint8_t* imageBase = reinterpret_cast<uint8_t*>(
        fnVirtualAlloc(reinterpret_cast<LPVOID>(preferredBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!imageBase) {
        imageBase = reinterpret_cast<uint8_t*>(
            fnVirtualAlloc(nullptr, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }
    if (!imageBase) return -16;

    // 1. Copy PE headers
    std::memcpy(imageBase, rawPe, nt->OptionalHeader.SizeOfHeaders);

    // 2. Map sections
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& sec = sections[i];
        if (sec.SizeOfRawData > 0) {
            if (static_cast<size_t>(sec.PointerToRawData) + sec.SizeOfRawData > rawSize) {
                return -17;
            }
            std::memcpy(imageBase + sec.VirtualAddress, rawPe + sec.PointerToRawData, sec.SizeOfRawData);
        }
    }

    // 3. Apply Base Relocations if ImageBase shifted
    const int64_t delta = reinterpret_cast<int64_t>(imageBase) - static_cast<int64_t>(preferredBase);
    if (delta != 0) {
        const auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relDir.VirtualAddress != 0 && relDir.Size != 0) {
            size_t parsed = 0;
            while (parsed < relDir.Size) {
                auto* blk = reinterpret_cast<const ImageRelocBlock*>(imageBase + relDir.VirtualAddress + parsed);
                if (blk->SizeOfBlock < sizeof(ImageRelocBlock)) break;
                const uint32_t count = (blk->SizeOfBlock - sizeof(ImageRelocBlock)) / sizeof(uint16_t);
                auto* entries = reinterpret_cast<const uint16_t*>(reinterpret_cast<const uint8_t*>(blk) + sizeof(ImageRelocBlock));
                for (uint32_t j = 0; j < count; ++j) {
                    uint16_t type = entries[j] >> 12;
                    uint16_t offset = entries[j] & 0x0FFFu;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        auto* patch = reinterpret_cast<int64_t*>(imageBase + blk->VirtualAddress + offset);
                        *patch += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        auto* patch = reinterpret_cast<int32_t*>(imageBase + blk->VirtualAddress + offset);
                        *patch += static_cast<int32_t>(delta);
                    }
                }
                parsed += blk->SizeOfBlock;
            }
        }
    }

    // 4. Resolve Import Address Table (IAT)
    const auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress != 0 && impDir.Size != 0) {
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(imageBase + impDir.VirtualAddress);
        while (desc->Name != 0) {
            const char* dllName = reinterpret_cast<const char*>(imageBase + desc->Name);
            HMODULE hDll = fnLoadLibraryA(dllName);
            if (!hDll) return -18;

            auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                imageBase + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            auto* iatThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(imageBase + desc->FirstThunk);

            while (origThunk->u1.AddressOfData != 0) {
                FARPROC fn = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) {
                    fn = fnGetProcAddress(hDll, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(origThunk->u1.Ordinal)));
                } else {
                    auto* impByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(imageBase + origThunk->u1.AddressOfData);
                    fn = fnGetProcAddress(hDll, reinterpret_cast<LPCSTR>(impByName->Name));
                }
                if (!fn) return -19;
                iatThunk->u1.Function = reinterpret_cast<ULONGLONG>(fn);
                ++origThunk;
                ++iatThunk;
            }
            ++desc;
        }
    }

    // 5. Update PEB->ImageBaseAddress so GetModuleHandle(NULL) matches loaded image
    if (auto* p = peb::get_peb()) {
        p->ImageBaseAddress = imageBase;
    }

    // 6. Apply strict per-section W^X permissions
    DWORD oldProt = 0;
    fnVirtualProtect(imageBase, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& sec = sections[i];
        SIZE_T protSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        if (protSize > 0) {
            DWORD prot = section_characteristics_to_protect(sec.Characteristics);
            fnVirtualProtect(imageBase + sec.VirtualAddress, protSize, prot, &oldProt);
        }
    }

    // 7. Register x64 SEH / C++ unwind exception handlers (.pdata)
    const auto& excDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (fnRtlAddFunc && excDir.VirtualAddress != 0 && excDir.Size != 0) {
        fnRtlAddFunc(
            reinterpret_cast<PRUNTIME_FUNCTION>(imageBase + excDir.VirtualAddress),
            excDir.Size / sizeof(RUNTIME_FUNCTION),
            reinterpret_cast<DWORD64>(imageBase));
    }

    if (fnFlushICache && fnGetCurProc) {
        fnFlushICache(fnGetCurProc(), imageBase, imageSize);
    }

    // 8. Invoke TLS callbacks if any
    const auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.VirtualAddress != 0 && tlsDir.Size != 0) {
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(imageBase + tlsDir.VirtualAddress);
        auto* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        if (callbacks) {
            while (*callbacks) {
                (*callbacks)(imageBase, DLL_PROCESS_ATTACH, nullptr);
                ++callbacks;
            }
        }
    }

    // 9. Transfer control to Original Entry Point (OEP)
    if (nt->OptionalHeader.AddressOfEntryPoint == 0) return -20;
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0) {
        auto dllEntry = reinterpret_cast<FnDllEntry>(imageBase + nt->OptionalHeader.AddressOfEntryPoint);
        return dllEntry(reinterpret_cast<HINSTANCE>(imageBase), DLL_PROCESS_ATTACH, nullptr) ? 0 : 1;
    } else {
        auto exeEntry = reinterpret_cast<FnExeEntry>(imageBase + nt->OptionalHeader.AddressOfEntryPoint);
        return exeEntry();
    }
}

} // namespace vmp::loader
