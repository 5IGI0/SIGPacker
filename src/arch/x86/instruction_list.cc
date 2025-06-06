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
#include <stdio.h>
#include <vector>

#include <cstring>

#include "polymorph.hh"

int x86_decode_instrs(uint8_t *buff, size_t bufflen, int mode, std::vector<poly_instr_t> &instrs, int &instr_id, uint64_t vaddr) {
    poly_instr_t instruction = {0};

    while (bufflen) {
        assert(ZYAN_SUCCESS(ZydisDisassembleIntel( // TODO: check error
            /* machine_mode:    */ (ZydisMachineMode)mode,
            /* runtime_address: */ vaddr,
            /* buffer:          */ buff,
            /* length:          */ bufflen,
            /* instruction:     */ &instruction.instruction
        )));
        instr_id++;
        instruction.addr            = buff;
        instruction.id              = instr_id;
        instruction.initial_vaddr   = vaddr;
        instrs.push_back(instruction);
        buff    += instruction.instruction.info.length;
        bufflen -= instruction.instruction.info.length;
        vaddr   += instruction.instruction.info.length;
        memset(&instruction, 0, sizeof(instruction.instruction));
    }

    return 0;
}

/**
TODO LIST:
[ ] handle nops that are larger than 1 byte for instruction insertion
  [ ] available_space
  [ ] insert instruction
[ ] check jump size (after correction) in available_space
*/

#define IS_REMOVABLE_NOP(instr) (                              \
    instr.instruction.info.mnemonic == ZYDIS_MNEMONIC_NOP  &&  \
    instr.instruction.info.length   == 1                   &&  \
    instr.is_position_dependent     == false               &&  \
    instr.is_jmp_dst                == false)

int x86_check_available_space(std::vector<poly_instr_t> &instrs, int offset) {
    int available_space = 0;

    // count nops before
    for (int i = offset-1; i >= 0; i--) {
        if (instrs[i].is_position_dependent)
            break; // if it is position dependent, we can't remove a nop that is before it

        if (IS_REMOVABLE_NOP(instrs[i]))
            available_space += instrs[i].instruction.info.length;
    }

    for (int i = offset; i < instrs.size(); i++) {
        if (instrs[i].is_position_dependent)
            break; // if it is position dependent, we can't move it to bring nops

        if (IS_REMOVABLE_NOP(instrs[i]))
            available_space += instrs[i].instruction.info.length;
    }

    return available_space;
}


int x86_insert_instr(poly_instr_t instr, std::vector<poly_instr_t> &instrs, int idx) {
    size_t needed_space = instr.instruction.info.length;
    if (x86_check_available_space(instrs, idx) < instr.instruction.info.length)
        return -1;

    for (int i = idx-1; i >= 0 && needed_space; i--) {
        if (instrs[i].is_position_dependent)
            break; // if it is position dependent, we can't remove a nop that is before it

        if (IS_REMOVABLE_NOP(instrs[i])) {
            auto it = instrs.begin();
            std::advance(it, i);
            instrs.erase(it);
            needed_space -= instrs[i].instruction.info.length;
            idx--;
            i++;
        }
    }

    for (int i = idx; i < instrs.size() && needed_space; i++) {
        if (instrs[i].is_position_dependent)
            break; // if it is position dependent, we can't move it to bring nops

        if (IS_REMOVABLE_NOP(instrs[i])) {
            auto it = instrs.begin();
            std::advance(it, i);
            instrs.erase(it);
            needed_space -= instrs[i].instruction.info.length;
            i--;
        }
    }

    auto it = instrs.begin();
    std::advance(it, idx);
    instrs.insert(it, instr);

    return idx;
}

void x86_update_addresses(std::vector<poly_instr_t> &instrs, uint64_t vaddr) {
    for (size_t i = 0; i < instrs.size(); i++) {
        instrs[i].instruction.runtime_address = vaddr;
        vaddr += instrs[i].instruction.info.length;
    }
}

void x86_apply_alternate(std::vector<poly_instr_t> &instrs, x86_alt_proposal_t alt, ZydisMachineMode machine_mode) {
    // 1. replace all target instrs by nops
    // 2. add alternates

    size_t       total_target_size = 0;
    poly_instr_t backup_instr = instrs[alt.target_idx];
    for (size_t i = 0; i < alt.target_count; i++) {
        total_target_size += instrs[alt.target_idx].instruction.info.length;
        auto it = instrs.begin();
        std::advance(it, alt.target_idx);
        instrs.erase(it); // TODO: free
    }

    poly_instr_t nop_instr = {
        .addr = (uint8_t *)"\x90",
        .instruction = {
            .info = {
                .mnemonic = ZYDIS_MNEMONIC_NOP,
                .length = 1},
            .text = "nop"}};
    for (size_t i = 0; i < total_target_size; i++) {
        auto it = instrs.begin();
        std::advance(it, alt.target_idx);
        instrs.insert(it, nop_instr);
    }

    std::vector<poly_instr_t> alt_instrs;
    int alt_id = 0;

    uint8_t *copbuf = (uint8_t *)malloc(alt.alt_instrs_size);
    memcpy(copbuf, alt.alt_instrs, alt.alt_instrs_size);

    x86_decode_instrs(copbuf, alt.alt_instrs_size, machine_mode, alt_instrs, alt_id);

    size_t target_idx = alt.target_idx;
    for (ssize_t i = alt_instrs.size() - 1; i >= 0; i--) {
        if (i == 0) {
            alt_instrs[0].id = backup_instr.id;
            alt_instrs[0].is_alloc = true;
        }
        alt_instrs[0].is_generated = true;
        target_idx = x86_insert_instr(alt_instrs[i], instrs, target_idx);
    }
}

void x86_free_instr_list(std::vector<poly_instr_t> &instrs) {
    for (size_t i = 0; i < instrs.size(); i++) {
        if (instrs[i].is_alloc) {
            free(instrs[i].addr);
        }
    }
    instrs.clear();
}