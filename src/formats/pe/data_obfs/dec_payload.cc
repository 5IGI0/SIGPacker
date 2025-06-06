/**
 * This file is part of SIGPacker. SIGPacker is free software:
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * SIGPacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with SIGPacker.
 * If not, see <https://www.gnu.org/licenses/>. 
 *
 * Copyright 2024, 2025 5IGI0 / Ethan L. C. Lorenzetti
**/

#include <cassert>
#include <cstdlib>
#include <string.h>
#include <vector>

#include "data_obfs.hh"

#include "../../../third/zydis/Zydis.h"
#include "../../../arch/x86/registers.h"

// TODO: optimize
static inline
uint64_t pe_add_instr_to_text(pe_file_t &pe, ZydisEncoderRequest &req) {
    ZyanU8      buff[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize   bufflen = ZYDIS_MAX_INSTRUCTION_LENGTH;

    assert(ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, buff, &bufflen)));

    uintptr_t ret = pe_append_section(pe, ".text", buff, bufflen);
    assert(ret && "dec payload add");

    return ((uint64_t)ret);
}

// TODO: optimize
static inline
uint64_t pe_add_instr_to_text_abs(pe_file_t &pe, ZydisEncoderRequest &req, uint64_t vaddr) {
    ZyanU8      buff[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize   bufflen = ZYDIS_MAX_INSTRUCTION_LENGTH;

    assert(ZYAN_SUCCESS(ZydisEncoderEncodeInstructionAbsolute(&req, buff, &bufflen, vaddr)));

    uintptr_t ret = pe_append_section(pe, ".text", buff, bufflen);
    assert(ret && "dec payload add");

    return ((uint64_t)ret);
}

static inline
int pe_get_random_reg(bool can_be_null) {
    return ((int[]){
            REG_RAX,
            REG_RBX,
            REG_RCX,
            REG_RDX,
            REG_RDI,
            REG_RSI,
            REG_NONE}[rand()%(6+can_be_null)]);
}

static inline
void pe_set_regs(
    ZydisRegister &idx_reg,
    ZydisRegister &buf_reg,
    ZydisRegister &base_reg,
    size_t bufsz,
    size_t addrsz
) {
    int idx, buf, base;

    idx = pe_get_random_reg(false);
    buf = pe_get_random_reg(false);
    while (idx == buf) buf = pe_get_random_reg(false);
    // TODO: can be null + use RIP (in 64) or displacement (in 32)
    base = pe_get_random_reg(false);
    while (base == buf || base == idx) base = pe_get_random_reg(false);

    idx_reg  = (ZydisRegister)x86_get_register_by_size(idx, addrsz);
    base_reg = (ZydisRegister)x86_get_register_by_size(base, addrsz);
    buf_reg  = (ZydisRegister)x86_get_register_by_size(buf, bufsz);
}

static inline
void pe_dec_payload(pe_file_t &pe, data_obfs_ctx_t &ctx, ZydisMachineMode mode) {
    ZydisRegister idx_reg;
    ZydisRegister buf_reg;
    ZydisRegister base_reg;

    uint64_t displacement = 0;
    if (ctx.vaddr&0xFFF && (rand() % 2) == 0) {
        // if it is not aligned we fake an aligned buffer with displacement
        // (actually the real check would be to check if it is at the begin of a section but i am too lazy to do that)
        uint64_t aligned_vaddr = ctx.vaddr&(~(uint64_t)0xFFF);
    
        // take random aligned base addr 
        uint64_t base_addr = (aligned_vaddr + (rand() % (ctx.vaddr - aligned_vaddr))) & ~(uint64_t)0xF;

        // just compute the displacement
        displacement = ctx.vaddr - base_addr;
    }

    size_t idx_scale = 1<<(rand()%3); // 1, 2 or 4.
    pe_set_regs(
        idx_reg, buf_reg, base_reg, 4,
        (PE_HDR(pe, ImageBase) > 0xFFFFFFFF) ? 8 : 4);

    /* generate the operand to get the target address independentely because we use it twice */
    ZydisEncoderOperand mempos_operand;
    memset(&mempos_operand, 0, sizeof(mempos_operand));
    mempos_operand.type             = ZYDIS_OPERAND_TYPE_MEMORY;
    mempos_operand.mem.base         = base_reg;
    mempos_operand.mem.index        = idx_reg;
    mempos_operand.mem.scale        = idx_scale;
    mempos_operand.mem.displacement = displacement;
    mempos_operand.mem.size         = 4;

    ZydisEncoderRequest req;
    memset(&req, 0, sizeof(req));

    req.machine_mode          = mode; // TODO: can also use mov/lea
    req.mnemonic              = ZYDIS_MNEMONIC_XOR;
    req.operand_count         = 2;
    req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = idx_reg;
    req.operands[1].type      = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[1].reg.value = idx_reg;
    pe_add_instr_to_text(pe, req);

    req.machine_mode          = mode;
    req.mnemonic              = ZYDIS_MNEMONIC_MOV;
    req.operand_count         = 2;
    req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = base_reg;
    req.operands[1].type      = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    req.operands[1].imm.u     = ctx.vaddr - displacement;
    pe_add_instr_to_text(pe, req);

    memset(&req, 0, sizeof(req));
    req.machine_mode          = mode;
    req.mnemonic              = ZYDIS_MNEMONIC_MOV;
    req.operand_count         = 2;
    req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = buf_reg;
    req.operands[1]           = mempos_operand;
    uint64_t loop_start = pe_add_instr_to_text(pe, req);

    for (size_t j = 0; j < ctx.op_count; j++) {
        req.machine_mode = mode;
        req.operand_count         = 2;
        req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
        req.operands[0].reg.value = buf_reg;
        req.operands[1].type      = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[1].imm.u     = ctx.ops[j].key;
        switch (ctx.ops[j].op_type) {
            case OBFS_OP_TYPE_ADD: req.mnemonic = ZYDIS_MNEMONIC_ADD; break;
            case OBFS_OP_TYPE_SUB: req.mnemonic = ZYDIS_MNEMONIC_SUB; break;
            case OBFS_OP_TYPE_XOR: req.mnemonic = ZYDIS_MNEMONIC_XOR; break;
            case OBFS_OP_TYPE_ROL: req.mnemonic = ZYDIS_MNEMONIC_ROL; break;
            case OBFS_OP_TYPE_ROR: req.mnemonic = ZYDIS_MNEMONIC_ROR; break;}
        pe_add_instr_to_text(pe, req);
    }

    memset(&req, 0, sizeof(req));
    req.machine_mode          = mode;
    req.mnemonic              = ZYDIS_MNEMONIC_MOV;
    req.operand_count         = 2;
    req.operands[0]           = mempos_operand;
    req.operands[1].type      = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[1].reg.value = buf_reg;
    pe_add_instr_to_text(pe, req);

    memset(&req, 0, sizeof(req)); // use inc if scale == 4, else use add
    if (idx_scale == 4 && ((rand()%2) == 0)) {
        req.machine_mode          = mode;
        req.mnemonic              = ZYDIS_MNEMONIC_INC;
        req.operand_count         = 1;
        req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
        req.operands[0].reg.value = idx_reg;
        pe_add_instr_to_text(pe, req);
    } else {
        req.machine_mode          = mode;
        req.mnemonic              = ZYDIS_MNEMONIC_ADD;
        req.operand_count         = 2;
        req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
        req.operands[0].reg.value = idx_reg;
        req.operands[1].type      = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[1].imm.u     = 4/idx_scale;
        pe_add_instr_to_text(pe, req);
    } // TODO: we can also use lea

    memset(&req, 0, sizeof(req));
    req.machine_mode          = mode;
    req.mnemonic              = ZYDIS_MNEMONIC_CMP;
    req.operand_count         = 2;
    req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = idx_reg;
    req.operands[1].type      = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    req.operands[1].imm.u     = ctx.len/idx_scale;
    pe_add_instr_to_text(pe, req);

    PIMAGE_SECTION_HEADER txt_hdr;
    assert(txt_hdr = pe_get_section(pe, ".text"));
    uint64_t rva = txt_hdr->VirtualAddress + txt_hdr->VirtualSize;
    memset(&req, 0, sizeof(req));
    req.machine_mode          = mode;
    req.mnemonic              = ZYDIS_MNEMONIC_JL;
    req.operand_count         = 1;
    req.operands[0].type      = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    req.operands[0].imm.u     = loop_start;
    pe_add_instr_to_text_abs(pe, req, rva);
}

void pe_add_dec_payloads(pe_file_t &pe, std::vector<data_obfs_ctx_t> &contexts) {
    ZydisMachineMode mode = pe.is_PE32 ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_64;

    uint64_t original_entry = PE_HDR(pe, AddressOfEntryPoint);
    PIMAGE_SECTION_HEADER txt_hdr;
    assert(txt_hdr = pe_get_section(pe, ".text"));
    PE_HDR(pe, AddressOfEntryPoint) = txt_hdr->VirtualAddress + txt_hdr->VirtualSize;

    for (auto &ctx : contexts)
        pe_dec_payload(pe, ctx, mode);

    // jump to entry point
    uint64_t jmp_from = txt_hdr->VirtualAddress + txt_hdr->VirtualSize + 5;
    unsigned char buf[5] = "\xE9";
    *(uint32_t *)&buf[1] = original_entry - jmp_from;
    pe_append_section(pe, ".text", buf, 5);
}