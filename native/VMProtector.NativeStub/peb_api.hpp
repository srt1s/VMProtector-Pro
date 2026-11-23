#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include "crypto.hpp"

namespace vmp::peb {

struct NativeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct NativeLdrEntry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    NativeUnicodeString FullDllName;
    NativeUnicodeString BaseDllName;
};

struct NativePeb {
    uint8_t  InheritedAddressSpace;
    uint8_t  ReadImageFileExecOptions;
    uint8_t  BeingDebugged;
    uint8_t  BitField;
    uint8_t  Padding0[4];
    PVOID    Mutant;
    PVOID    ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID    ProcessParameters;
    PVOID    SubSystemData;
    PVOID    ProcessHeap;
    PVOID    FastPebLock;
    PVOID    AtlThunkSListPtr;
    PVOID    IFEOKey;
    uint32_t CrossProcessFlags;
    uint8_t  Padding1[4];
    PVOID    UserSharedInfoPtr;
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    PVOID    ApiSetMap;
    uint32_t TlsExpansionCounter;
    uint8_t  Padding2[4];
    PVOID    TlsBitmap;
    uint32_t TlsBitmapBits[2];
    PVOID    ReadOnlySharedMemoryBase;
    PVOID    SharedData;
    PVOID*   ReadOnlyStaticServerData;
    PVOID    AnsiCodePageData;
    PVOID    OemCodePageData;
    PVOID    UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag;
};

inline NativePeb* get_peb() noexcept {
#ifdef _M_X64
    return reinterpret_cast<NativePeb*>(__readgsqword(0x60));
#else
    return reinterpret_cast<NativePeb*>(__readfsdword(0x30));
#endif
}

inline HMODULE find_module_by_hash(uint64_t lowerNameHash) noexcept {
    NativePeb* p = get_peb();
    if (!p || !p->Ldr) return nullptr;

    LIST_ENTRY* head = &p->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        auto* entry = CONTAINING_RECORD(cur, NativeLdrEntry, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            size_t count = entry->BaseDllName.Length / sizeof(wchar_t);
            if (crypto::fnv1a64_icase_w(entry->BaseDllName.Buffer, count) == lowerNameHash) {
                return reinterpret_cast<HMODULE>(entry->DllBase);
            }
        }
    }
    return nullptr;
}

inline void* find_export_by_hash(HMODULE mod, uint64_t procNameHash) noexcept {
    if (!mod) return nullptr;
    auto* base = reinterpret_cast<const uint8_t*>(mod);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return nullptr;

    auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<const uint32_t*>(base + exp->AddressOfNames);
    auto* ordinals = reinterpret_cast<const uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<const uint32_t*>(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (crypto::fnv1a64(name) == procNameHash) {
            uint32_t rva = funcs[ordinals[i]];
            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
                // Forwarded export: skip direct resolution and fall back cleanly
                return nullptr;
            }
            return const_cast<uint8_t*>(base + rva);
        }
    }
    return nullptr;
}

template <typename Fn>
inline Fn resolve(uint64_t dllLowerHash, uint64_t procHash) noexcept {
    HMODULE mod = find_module_by_hash(dllLowerHash);
    if (!mod) return nullptr;
    return reinterpret_cast<Fn>(find_export_by_hash(mod, procHash));
}

inline constexpr uint64_t HASH_KERNEL32 = crypto::fnv1a64("kernel32.dll");
inline constexpr uint64_t HASH_NTDLL    = crypto::fnv1a64("ntdll.dll");

} // namespace vmp::peb
