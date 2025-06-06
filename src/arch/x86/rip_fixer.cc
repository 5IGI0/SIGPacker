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

#include <cstring>

#include "registers.h"
#include "polymorph.hh"

void x86_find_rips(std::vector<poly_instr_t> &instrs) {
    for (size_t i = 0; i < instrs.size(); i++) {
        for (size_t op_idx = 0; op_idx < instrs[i].instruction.info.operand_count_visible; op_idx++) {
            switch (instrs[i].instruction.operands[op_idx].type) {
                case ZYDIS_OPERAND_TYPE_MEMORY:
                    if (x86_get_unsized_register(instrs[i].instruction.operands[op_idx].mem.base) == REG_RIP) {
                        instrs[i].is_position_dependent = instrs[i].instruction.operands[op_idx].mem.disp.has_displacement == false;
                        instrs[i].use_ip = true;
                    } else if (x86_get_unsized_register(instrs[i].instruction.operands[op_idx].mem.index) == REG_RIP) {
                        instrs[i].is_position_dependent = true; // TODO: patch rip when used as index
                        instrs[i].use_ip = true;
                    }
                    break;
                case ZYDIS_OPERAND_TYPE_REGISTER:
                    if (x86_get_unsized_register(instrs[i].instruction.operands[op_idx].reg.value) == REG_RIP) {
                        instrs[i].is_position_dependent = true;
                        instrs[i].use_ip = true;
                    }
                    break;
                default: break;
            }
        }
    }
}

void x86_fix_rips(std::vector<poly_instr_t> &instrs) {
    for (size_t i = 0; i < instrs.size(); i++) {
        if (instrs[i].is_position_dependent) continue;
        for (size_t op_idx = 0; op_idx < instrs[i].instruction.info.operand_count_visible; op_idx++) {
            if (
                instrs[i].instruction.operands[op_idx].type == ZYDIS_OPERAND_TYPE_MEMORY && // TODO register
                instrs[i].instruction.operands[op_idx].mem.base == ZYDIS_REGISTER_RIP &&
                instrs[i].instruction.operands[op_idx].mem.disp.has_displacement) {
                ZydisEncoderRequest req;
                assert(ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(&instrs[i].instruction.info, instrs[i].instruction.operands, instrs[i].instruction.info.operand_count_visible, &req)));
                req.operands[op_idx].mem.displacement -= (instrs[i].instruction.runtime_address - instrs[i].initial_vaddr);

                ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
                ZyanUSize encoded_length = sizeof(encoded_instruction);

                assert(ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)));
                assert(instrs[i].instruction.info.length == encoded_length); // TODO: handle it properly

                instrs[i].is_alloc  = true;
                instrs[i].addr      = (uint8_t *)malloc(encoded_length);
                memcpy(instrs[i].addr, encoded_instruction, encoded_length);
                break;
            }
        }
    }
}