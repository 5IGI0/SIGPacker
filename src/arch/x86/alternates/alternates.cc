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
#include <cstdio>
#include <cstring>
#include <stdlib.h>

#include "alternates.hh"

#include "../polymorph.hh"

static void x86_find_alternate_operands(
    std::vector<poly_instr_t> &instrs, 
    size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &proposals,
    ZydisMachineMode machine_mode
) {
    auto &instr = instrs[idx];

    for (size_t i = 0; i < instr.instruction.info.operand_count_visible; i++) {
        auto &op = instr.instruction.operands[i];

        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if ( // invert mem operands
                op.mem.base  != ZYDIS_REGISTER_NONE &&
                op.mem.index != ZYDIS_REGISTER_NONE &&
                op.mem.index != op.mem.base &&
                op.mem.scale == 1) {
                ZydisEncoderRequest req = {};
                assert(ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
                    &instr.instruction.info,
                    instr.instruction.operands,
                    instr.instruction.info.operand_count_visible,
                    &req)));
                
                ZydisRegister tmp = req.operands[i].mem.base;
                req.operands[i].mem.base = req.operands[i].mem.index;
                req.operands[i].mem.index = tmp;
                
                x86_add_proposal(req, idx, 1, free_space, instrs, proposals);
            }
        }
    }
}

void x86_find_alternate(
    std::vector<poly_instr_t> &instrs,
    size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &proposals,
    ZydisMachineMode machine_mode
) {
    auto &instr = instrs[idx];

    // if it's conditional, we might break the condition
    // by changing it to another op that dont set the right flags.
    if (instr.is_conditional || instr.is_position_dependent || instr.is_generated || instr.use_ip)
        return;

    x86_find_alternate_operands(instrs, idx, free_space, proposals, machine_mode);

    switch (instr.instruction.info.mnemonic) {
        case ZYDIS_MNEMONIC_ADD: return x86_find_alternate_add(instrs, idx, free_space, proposals, machine_mode);
        case ZYDIS_MNEMONIC_SUB: return x86_find_alternate_sub(instrs, idx, free_space, proposals, machine_mode);
        case ZYDIS_MNEMONIC_MOV: return x86_find_alternate_mov(instrs, idx, free_space, proposals, machine_mode);
        case ZYDIS_MNEMONIC_LEA: return x86_find_alternate_lea(instrs, idx, free_space, proposals, machine_mode);
        default: return;
    }
}

void x86_find_alternates(std::vector<poly_instr_t> &instrs, std::vector<x86_alt_proposal_t> &proposals, ZydisMachineMode machine_mode) {
    for (size_t i = 0; i < instrs.size(); i++) {
        x86_find_alternate(instrs, i, x86_check_available_space(instrs, i), proposals, machine_mode);
    }
}

void x86_free_alternates(std::vector<x86_alt_proposal_t> &proposals) {
    for (size_t i = 0; i < proposals.size(); i++) {
        free(proposals[i].alt_instrs);
    }
    proposals.clear();
}