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
#include <cstdint>

void x86_find_alternate_mov(
    std::vector<poly_instr_t> &instrs, 
    size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &proposals,
    ZydisMachineMode machine_mode
) {
    auto &instr = instrs[idx];

    ZydisEncoderRequest req;

    // mov a,b -> lea a,[b] (b = register)
    if (
        instr.instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        instr.instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
    ) {
        memset(&req, 0, sizeof(req));
        req.machine_mode          = machine_mode;
        req.mnemonic              = ZYDIS_MNEMONIC_LEA;
        req.operand_count         = 2;
        req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
        req.operands[0].reg.value = instr.instruction.operands[0].reg.value;

        req.operands[1].type        = ZYDIS_OPERAND_TYPE_MEMORY;
        req.operands[1].mem.base    = instr.instruction.operands[1].reg.value;
        req.operands[1].mem.size  = ((ZyanU16)ZydisRegisterGetWidth(machine_mode, instr.instruction.operands[0].reg.value))/8;

        x86_add_proposal(req, idx, 1, free_space, instrs, proposals);
    } else if (
        // mov a,b -> lea a,[b] (b = immediate)
        instr.instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER  &&
        instr.instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
        instr.instruction.operands[1].imm.value.u <= INT32_MAX
    ) {
        memset(&req, 0, sizeof(req));
        req.machine_mode          = machine_mode;
        req.mnemonic              = ZYDIS_MNEMONIC_LEA;
        req.operand_count         = 2;
        req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
        req.operands[0].reg.value = instr.instruction.operands[0].reg.value;

        req.operands[1].type             = ZYDIS_OPERAND_TYPE_MEMORY;
        req.operands[1].mem.displacement = instr.instruction.operands[1].imm.value.s;
        // TODO: what the hell is this value supposed to be
        req.operands[1].mem.size = 8;// ((ZyanU16)ZydisRegisterGetWidth(machine_mode, instr.instruction.operands[0].reg.value))/8;

        x86_add_proposal(req, idx, 1, free_space, instrs, proposals);
    }
}
