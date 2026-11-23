#pragma once
#include <cstdint>
#include <cstddef>
#include "crypto.hpp"
#include "anti_debug.hpp"

namespace vmp::vm {

// Semantic VM opcodes (mapped through per-build opcodeTable[256] at runtime)
enum class SemanticOp : uint8_t {
    Nop          = 0x00,
    PushImm64    = 0x01, // [u64]
    LoadReg      = 0x02, // [u8 reg]
    StoreReg     = 0x03, // [u8 reg]
    Add64        = 0x04,
    Sub64        = 0x05,
    Xor64        = 0x06,
    Mul64        = 0x07,
    Rol64        = 0x08, // [u8 shift]
    Ror64        = 0x09, // [u8 shift]
    ProbeDebug   = 0x0A, // pushes debug flags onto stack
    EmitKeyWord  = 0x0B, // [u8 wordIdx 0..3] writes stack top into derivedKey[wordIdx]
    MixHash      = 0x0C, // FNV-1a mix of stack top
    Dup          = 0x0D,
    Swap         = 0x0E,
    Halt         = 0xFF
};

#pragma pack(push, 1)
struct VmpSectionBundleHeader {
    uint32_t magic;            // 'XPMV' = 0x58504D56
    uint16_t version;          // 2
    uint16_t flags;            // bit 0: antiDebug enabled
    uint8_t  opcodeMap[256];   // physical byte opcode -> SemanticOp
    uint8_t  vmSalt[16];       // XOR mask for bytecode stream
    uint32_t vmBytecodeLen;
    uint32_t vmBytecodeCrc;
    uint8_t  nonce[12];
    uint32_t payloadRawLen;
    uint32_t payloadCrc;
    uint64_t expectedDebugMask; // 0 when clean
};
#pragma pack(pop)

inline bool execute_key_vm(const VmpSectionBundleHeader& hdr,
                           const uint8_t* encVmCode,
                           uint8_t outKey[32],
                           bool antiDebugEnabled) noexcept {
    if (hdr.vmBytecodeLen == 0 || hdr.vmBytecodeLen > 65536) return false;

    uint8_t code[65536]{};
    for (uint32_t i = 0; i < hdr.vmBytecodeLen; ++i) {
        code[i] = encVmCode[i] ^ hdr.vmSalt[i & 15u] ^ static_cast<uint8_t>((i * 0x5Du) & 0xFFu);
    }

    if (crypto::crc32_ieee(code, hdr.vmBytecodeLen) != hdr.vmBytecodeCrc) {
        return false;
    }

    uint64_t regs[16]{};
    uint64_t stack[256]{};
    uint64_t keyWords[4]{};
    int sp = 0;
    uint32_t pc = 0;
    bool halted = false;

    auto push = [&](uint64_t v) noexcept {
        if (sp < 256) stack[sp++] = v;
    };
    auto pop = [&]() noexcept -> uint64_t {
        return sp > 0 ? stack[--sp] : 0ULL;
    };

    uint32_t steps = 0;
    while (pc < hdr.vmBytecodeLen && !halted && steps++ < 100000u) {
        uint8_t phys = code[pc++];
        SemanticOp op = static_cast<SemanticOp>(hdr.opcodeMap[phys]);

        switch (op) {
            case SemanticOp::Nop:
                break;

            case SemanticOp::PushImm64: {
                if (pc + 8 > hdr.vmBytecodeLen) return false;
                uint64_t v = 0;
                for (int i = 0; i < 8; ++i) {
                    v |= static_cast<uint64_t>(code[pc++]) << (i * 8);
                }
                push(v);
                break;
            }

            case SemanticOp::LoadReg: {
                if (pc >= hdr.vmBytecodeLen) return false;
                uint8_t r = code[pc++] & 0x0Fu;
                push(regs[r]);
                break;
            }

            case SemanticOp::StoreReg: {
                if (pc >= hdr.vmBytecodeLen) return false;
                uint8_t r = code[pc++] & 0x0Fu;
                regs[r] = pop();
                break;
            }

            case SemanticOp::Add64: {
                uint64_t b = pop();
                uint64_t a = pop();
                push(a + b);
                break;
            }

            case SemanticOp::Sub64: {
                uint64_t b = pop();
                uint64_t a = pop();
                push(a - b);
                break;
            }

            case SemanticOp::Xor64: {
                uint64_t b = pop();
                uint64_t a = pop();
                push(a ^ b);
                break;
            }

            case SemanticOp::Mul64: {
                uint64_t b = pop();
                uint64_t a = pop();
                push(a * b);
                break;
            }

            case SemanticOp::Rol64: {
                if (pc >= hdr.vmBytecodeLen) return false;
                uint8_t sh = code[pc++] & 63u;
                push(crypto::rotl64(pop(), sh));
                break;
            }

            case SemanticOp::Ror64: {
                if (pc >= hdr.vmBytecodeLen) return false;
                uint8_t sh = code[pc++] & 63u;
                push(crypto::rotr64(pop(), sh));
                break;
            }

            case SemanticOp::ProbeDebug: {
                uint64_t f = antiDebugEnabled ? static_cast<uint64_t>(antidebug::probe_environment_flags()) : 0ULL;
                // Spread non-zero tamper bits silently across the full 64-bit word
                if (f != 0) {
                    f = (f * 0x9E3779B97F4A7C15ULL) ^ 0xD1B54A32D192ED03ULL;
                }
                push(f);
                break;
            }

            case SemanticOp::EmitKeyWord: {
                if (pc >= hdr.vmBytecodeLen) return false;
                uint8_t idx = code[pc++] & 3u;
                keyWords[idx] = pop();
                break;
            }

            case SemanticOp::MixHash: {
                uint64_t v = pop();
                v ^= v >> 30;
                v *= 0xBF58476D1CE4E5B9ULL;
                v ^= v >> 27;
                v *= 0x94D049BB133111EBULL;
                v ^= v >> 31;
                push(v);
                break;
            }

            case SemanticOp::Dup: {
                if (sp > 0) push(stack[sp - 1]);
                break;
            }

            case SemanticOp::Swap: {
                if (sp >= 2) {
                    uint64_t tmp = stack[sp - 1];
                    stack[sp - 1] = stack[sp - 2];
                    stack[sp - 2] = tmp;
                }
                break;
            }

            case SemanticOp::Halt:
                halted = true;
                break;

            default:
                return false;
        }
    }

    for (int w = 0; w < 4; ++w) {
        for (int b = 0; b < 8; ++b) {
            outKey[w * 8 + b] = static_cast<uint8_t>((keyWords[w] >> (b * 8)) & 0xFFu);
        }
    }
    return halted;
}

} // namespace vmp::vm
