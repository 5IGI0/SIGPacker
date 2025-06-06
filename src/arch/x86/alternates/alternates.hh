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

#ifndef ARCH_X86_ALTERNATES_ALTERNATES_HH
#define ARCH_X86_ALTERNATES_ALTERNATES_HH

#include <cassert>
#include <cstdio>
#include <cstring>
#include <stdlib.h>

#include "../polymorph.hh"

#include "../../../utils.h"


void x86_find_alternate_add(
    std::vector<poly_instr_t> &instrs, size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &p, ZydisMachineMode mode);
void x86_find_alternate_sub(
    std::vector<poly_instr_t> &instrs, size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &p, ZydisMachineMode mode);
void x86_find_alternate_mov(
    std::vector<poly_instr_t> &instrs, size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &p, ZydisMachineMode mode);
void x86_find_alternate_lea(
    std::vector<poly_instr_t> &instrs, size_t idx, size_t free_space,
    std::vector<x86_alt_proposal_t> &p, ZydisMachineMode mode);

static inline
void x86_add_proposal(
    ZydisEncoderRequest &req,
    size_t target_idx,
    size_t target_count,
    size_t free_space,
    std::vector<poly_instr_t> &instrs,
    std::vector<x86_alt_proposal_t> &proposals
) {
    ZyanU8      buff[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize   bufflen = ZYDIS_MAX_INSTRUCTION_LENGTH;

    assert(ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, buff, &bufflen)));
    if (bufflen <= (instrs[target_idx].instruction.info.length + free_space)) { // TODO: sum if target_count > 1
        proposals.push_back(x86_alt_proposal_t{
            .target_idx = target_idx,
            .target_count = target_count,
            .alt_instrs = memdup(buff, bufflen),
            .alt_instrs_size = bufflen});
    }
}

static inline
void x86_add_proposal_m(
    ZydisEncoderRequest *req,
    size_t req_count,
    size_t target_idx,
    size_t target_count,
    size_t free_space,
    std::vector<poly_instr_t> &instrs,
    std::vector<x86_alt_proposal_t> &proposals) {
    ZyanU8      buff[ZYDIS_MAX_INSTRUCTION_LENGTH * req_count];
    ZyanUSize   bufflen;
    size_t      buff_offset = 0;

    for (size_t i = 0; i < req_count; i++) {
        bufflen = ZYDIS_MAX_INSTRUCTION_LENGTH;

        assert(ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(req + i, buff + buff_offset, &bufflen)));

        if ((buff_offset + bufflen) > (instrs[target_idx].instruction.info.length + free_space)) // TODO: sum if target_count > 1
            return;

        buff_offset += bufflen;
    }

    proposals.push_back(x86_alt_proposal_t{
        .target_idx = target_idx,
        .target_count = target_count,
        .alt_instrs = memdup(buff, buff_offset),
        .alt_instrs_size = buff_offset});
}
#endif