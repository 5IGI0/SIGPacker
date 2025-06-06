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
#include <iostream>
#include <vector>
#include <cstdlib>
#include <cstring>

#include "polymorph.hh"

#include "../../third/zydis/Zydis.h"

static bool is_jump(int mnemonic) {
    switch (mnemonic) {
        /* call are actual jumps */
        case ZYDIS_MNEMONIC_CALL:
        /* usual jumps */
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        // case ZYDIS_MNEMONIC_JKNZD: // NOTE: seems like they are not "standard" instructions
        // case ZYDIS_MNEMONIC_JKZD:  // and they are not described in x86reference.xml
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JZ:
            return true;
        default:
            return false;
    }
}

void x86_find_jump_destinations(std::vector<poly_instr_t> &instrs) {
    for (size_t i = 0; i < instrs.size(); i++) {
        if (!is_jump(instrs[i].instruction.info.mnemonic))
            continue;

        if (instrs[i].instruction.info.operand_count_visible    != 1 ||
            instrs[i].instruction.operands[0].type              != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            // std::cerr << "Warning: unexpected combination jmp/addr" << std::endl;
            instrs[i].is_position_dependent = true;
            continue;
        }

        instrs[i].is_patchable_jump = true;
        intptr_t target_addr = 
            instrs[i].instruction.runtime_address +
            instrs[i].instruction.operands[0].imm.value.s +
            instrs[i].instruction.info.length;
        
        if (target_addr < instrs[0].instruction.runtime_address || target_addr > instrs[instrs.size()-1].instruction.runtime_address) {
            // std::cerr << "Warning: jump out of frame" << std::endl;
            instrs[i].jump_info.instr_id    = 0;
            continue;
        }

        bool success = false;
        for (size_t y = 0; y < instrs.size(); y++) {
            if (instrs[y].instruction.runtime_address == target_addr) {
                success = true;
                instrs[y].is_jmp_dst = true;
                instrs[i].jump_info.instr_id = instrs[y].id;
                instrs[i].jump_info.offset   = 0;
                break;
            }
        }

        if (!success) {
            std::cerr << "Warning: jump inside instruction" << std::endl;
            exit(0);
        }
    }
}

int x86_fix_jumps(std::vector<poly_instr_t> &instrs) {
    x86_update_addresses(instrs);

    for (size_t i = 0; i < instrs.size(); i++) {
        if (!instrs[i].is_patchable_jump)
            continue;

        intptr_t rel_addr = instrs[i].instruction.operands[0].imm.value.s;

        if (instrs[i].jump_info.instr_id == 0) {
            rel_addr -= (instrs[i].instruction.runtime_address - instrs[i].initial_vaddr) - instrs[i].instruction.info.length;
        } else {
            uintptr_t offset = 0;
            bool success = false;
            for (auto &instr : instrs) {
                if (instr.id == instrs[i].jump_info.instr_id) {
                    rel_addr = offset - (instrs[i].instruction.runtime_address - instrs[0].instruction.runtime_address);
                    success = true;
                }
                offset += instr.instruction.info.length;
            }
            if (!success) {
                std::cerr << "unable to find jump destination (jump fixing)" << std::endl;
                exit(0);
            }
        }

        uint8_t *instr_data = (uint8_t *)malloc(instrs[i].instruction.info.length);

        if (instrs[i].instruction.info.length > 4) { // assuming it is 32bits operand
            memcpy(instr_data, instrs[i].addr, instrs[i].instruction.info.length-4);
            rel_addr -= instrs[i].instruction.info.length;
            int32_t rel_addr32 = rel_addr;
            memcpy(
                instr_data+instrs[i].instruction.info.length-4,
                &rel_addr32, // assumes little-endian host
                4);
        } else { // assuming 8bits operand
            memcpy(instr_data, instrs[i].addr, instrs[i].instruction.info.length-1);
            rel_addr -= instrs[i].instruction.info.length;
            assert(rel_addr < 0x80 && rel_addr >= -0x80); // is 8bits value + TODO:
            int8_t rel_addr8 = rel_addr;
            instr_data[instrs[i].instruction.info.length-1] = rel_addr8;
        }

        instrs[i].is_alloc  = true;
        instrs[i].addr      = instr_data;
    }

    return 0;
}