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

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <vector>

#include <cstring>

#include "../../third/zydis/Zydis.h"

#include "commutative.hh"
#include "polymorph.hh"
#include "conditional_dependence.hh"
#include "jumps.hh"

/*
1. disassemble
2. analyse
3. modify
4. reassemble
*/

static void x86_debug_print(std::vector<poly_instr_t> &instrs) {
    int i = -1;
    std::cout << "ADDR    FREE FLAGS  GID  INSTR" << std::endl;
    for (auto instr : instrs) {
        char flags[] = "[    ]";
        i++;

        flags[1] = instr.is_commutative         ? 'c' : ' ';
        flags[2] = instr.is_conditional         ? '?' : ' ';
        flags[3] = instr.is_jmp_dst             ? 'D' : ' ';
        flags[4] = instr.is_position_dependent  ? 'p' : ' ';

        std::cout
            << std::hex << instr.instruction.runtime_address << std::dec << " [" <<
            std::setw(3) << x86_check_available_space(instrs, i) << "]"
            << flags << " " << std::setw(3) << instr.group_id << std::setw(0) << ": " << instr.instruction.text << std::endl;
    }
}

int polyform_x86_r(uint8_t *buff, uint8_t *outbuff, size_t bufflen, int mode) {
    std::vector<poly_instr_t> instrs;
    int group_id = 0;
    int instr_id = 0;

    x86_decode_instrs(buff, bufflen, mode, instrs, instr_id);
    x86_find_rips(instrs);
    x86_find_jump_destinations(instrs);
    x86_group_conditional_ops(instrs, group_id);
    x86_group_commutative_ops(instrs, group_id);

    // x86_debug_print(instrs);

    /* shuffle commutatives */
    for (auto it = instrs.begin(); it != instrs.end(); ++it) {
        if (!it->is_commutative)
            continue;

        auto end_it = it;
        int begin_instr_id = it->id;

        while (end_it != instrs.end() && end_it->group_id == it->group_id)
            end_it++;

        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(it, end_it, g);

        for (size_t j = 0; j < instrs.size(); j++) {
            if (instrs[j].jump_info.instr_id == begin_instr_id)
                instrs[j].jump_info.instr_id = it->id;
        }
    }

    /* move nops (TODO: junk code) */
    // for (size_t i = 0; i < instrs.size(); i++) {
    //     if (i != 0 && instrs[i].is_conditional && instrs[i-1].group_id == instrs[i].group_id)
    //         continue; // can't add junk code between conditionals

    //     // TODO: change it so that it's evenly distributed
    //     if (rand()%7 == 0) {
    //         if (x86_check_available_space(instrs, i) == 0)
    //             continue;

    //         poly_instr_t instr = {0};
    //         instr.addr = (uint8_t *)"\x90";
    //         instr.instruction.info.length = 1;
    //         memcpy(instr.instruction.text, "nop", 4);
    //         i = x86_insert_instr(instr, instrs, i);
    //         if (i < 0)  break;
    //     }
    // }

    std::vector<x86_alt_proposal_t> proposals;
    for (size_t i = 1; i <= 20; i++) {
        x86_free_alternates(proposals);
        x86_find_alternates(instrs, proposals, (ZydisMachineMode)mode);

        // TODO: find the right value to maximize possibilities & signature-proofness
        if (proposals.size() / 2 < i)
            break;
        if (proposals.size() == 1 && rand() % 2)
            break;

        x86_apply_alternate(instrs, proposals[rand() % proposals.size()], (ZydisMachineMode)mode);
    }

    x86_free_alternates(proposals);
    x86_fix_jumps(instrs);
    x86_fix_rips(instrs);

    size_t i = 0;
    memcpy(outbuff, buff, bufflen);
    for (auto &instr : instrs) {
        memcpy(outbuff+i, instr.addr, instr.instruction.info.length);
        i += instr.instruction.info.length;
    }

    x86_free_instr_list(instrs);

    return 0;
}

int polyform_x86(uint8_t *buff, size_t bufflen, int mode) {
    uint8_t *outbuff = (uint8_t *)malloc(bufflen);
    assert(outbuff);

    int ret = polyform_x86_r(buff, outbuff, bufflen, mode);
    if (ret >= 0) {
        memcpy(buff, outbuff, bufflen);
    }
    free(outbuff);
    return ret;
}