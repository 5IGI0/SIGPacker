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

#include "alternates.hh"

void x86_find_alternate_lea(
    std::vector<poly_instr_t> &instrs, 
    size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &proposals,
    ZydisMachineMode machine_mode
) {
    auto &instr = instrs[idx];

    if (
        instr.instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        instr.instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
    ) {
        ZydisEncoderRequest req[2];
        memset(req, 0, sizeof(req));

        assert(ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
                    &instr.instruction.info,
                    instr.instruction.operands,
                    instr.instruction.info.operand_count_visible,
                    &req[0])));

        if (req[0].operands[1].mem.displacement != 0) {
            if (req[0].operands[1].mem.base  != ZYDIS_REGISTER_NONE || 
                req[0].operands[1].mem.index != ZYDIS_REGISTER_NONE) {
                // lea a, [b+c*d+e]
                // to
                // lea a, [b+c*d]
                // add a, e
                req[1].machine_mode      = machine_mode;
                req[1].mnemonic          = ZYDIS_MNEMONIC_ADD;
                req[1].operand_count     = 2;
                req[1].operands[0].type  = ZYDIS_OPERAND_TYPE_REGISTER;
                req[1].operands[0].reg   = req[0].operands[0].reg;
                req[1].operands[1].type  = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                req[1].operands[1].imm.s = req[0].operands[1].mem.displacement;
                
                req[0].operands[1].mem.displacement = 0;
                x86_add_proposal_m(req, 2, idx, 1, free_space, instrs, proposals);
                req[0].operands[1].mem.displacement = req[1].operands[0].imm.s;
            } else { // TODO: is it possible?
                req[1].machine_mode      = machine_mode;
                req[1].mnemonic          = ZYDIS_MNEMONIC_MOV;
                req[1].operand_count     = 2;
                req[1].operands[0].type  = ZYDIS_OPERAND_TYPE_REGISTER;
                req[1].operands[0].reg   = req[0].operands[0].reg;
                req[1].operands[1].type  = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                req[1].operands[1].imm.s = req[0].operands[1].mem.displacement;
                x86_add_proposal(req[1], idx, 1, free_space, instrs, proposals);
            }
        }
    }
}