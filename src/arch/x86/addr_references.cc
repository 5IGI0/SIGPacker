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

#include <cstdint>
#include <cstddef>
#include <vector>

#include "polymorph.hh"
#include "registers.h"

#include "../../third/zydis/Zydis.h"

static inline
void x86_list_references_64(std::vector<poly_instr_t> &instrs, std::vector<uint64_t> &refs) {
    for (size_t i = 0; i < instrs.size(); i++) {
        for (size_t j = 0; j < instrs[i].instruction.info.operand_count; j++) {
            auto &op = instrs[i].instruction.operands[j];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (x86_get_unsized_register(op.mem.base) == REG_RIP || x86_get_unsized_register(op.mem.index) == REG_RIP)
                    refs.push_back(instrs[i].initial_vaddr + op.mem.disp.value + instrs[i].instruction.info.length);
            }
        }
    }
}

static inline
void x86_list_references_32(std::vector<poly_instr_t> &instrs, std::vector<uint64_t> &refs) {
    for (size_t i = 0; i < instrs.size(); i++) {
        for (size_t j = 0; j < instrs[i].instruction.info.operand_count; j++) {
            auto &op = instrs[i].instruction.operands[j];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (op.mem.disp.has_displacement && op.mem.disp.value > 0) {
                    refs.push_back(op.mem.disp.value);
                }
            } else if (op.type == ZYDIS_OPERAND_TYPE_POINTER) {
               refs.push_back(op.ptr.offset); 
            } else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                if (op.imm.value.s > 0) refs.push_back(op.imm.value.u);
            }
        }
    }
}

void x86_list_references(uint8_t *buff, size_t bufflen, int mode, uint64_t vaddr, std::vector<uint64_t> &refs) {
    std::vector<poly_instr_t> instrs;
    int instr_id;

    refs.clear();
    x86_decode_instrs(buff, bufflen, mode, instrs, instr_id, vaddr);

    if (mode == ZYDIS_MACHINE_MODE_LONG_64) {
        x86_list_references_64(instrs, refs);
    } else {
        x86_list_references_32(instrs, refs);
    }
}