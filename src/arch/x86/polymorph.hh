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

#ifndef ARCH_X86_POLYMORPH_HH
#define ARCH_X86_POLYMORPH_HH

#include <vector>

#include <cstddef>
#include <cstdint>

#include "../../third/zydis/Zydis.h"

typedef struct {
    uint8_t     *addr;
    uint64_t     initial_vaddr;
    int         id;
    int         group_id;
    bool        is_generated;
    bool        is_alloc;
    bool        is_commutative;
    bool        is_conditional;
    bool        is_jmp_dst;
    bool        is_position_dependent;
    bool        is_patchable_jump;
    bool        use_ip;
    struct {
        int     instr_id; // 0 = out of frame (offset is computed from the begin)
        int32_t offset;
    } jump_info;

    ZydisDisassembledInstruction instruction;
} poly_instr_t;

typedef struct {
    size_t  target_idx;
    size_t  target_count;
    uint8_t *alt_instrs;
    size_t  alt_instrs_size;
} x86_alt_proposal_t;

#define X86_DEFAULT_INSTR_LIST_VADDR (1 << 30)

int     polyform_x86(uint8_t *buff, size_t bufflen, int mode);
int     polyform_x86_r(uint8_t *buff, uint8_t *outbuff, size_t bufflen, int mode);
int     x86_decode_instrs(uint8_t *buff, size_t bufflen, int mode, std::vector<poly_instr_t> &instrs, int &instr_id, uint64_t vaddr=X86_DEFAULT_INSTR_LIST_VADDR);
int     x86_check_available_space(std::vector<poly_instr_t> &instrs, int offset);
int     x86_insert_instr(poly_instr_t instr, std::vector<poly_instr_t> &instrs, int idx);
void    x86_update_addresses(std::vector<poly_instr_t> &instrs, uint64_t vaddr=X86_DEFAULT_INSTR_LIST_VADDR);
void    x86_find_rips(std::vector<poly_instr_t> &instrs);
void    x86_fix_rips(std::vector<poly_instr_t> &instrs);
void    x86_find_alternates(std::vector<poly_instr_t> &instrs, std::vector<x86_alt_proposal_t> &proposals, ZydisMachineMode machine_mode);
void    x86_free_alternates(std::vector<x86_alt_proposal_t> &proposals);
void    x86_apply_alternate(std::vector<poly_instr_t> &instrs, x86_alt_proposal_t alt, ZydisMachineMode machine_mode);
void    x86_free_instr_list(std::vector<poly_instr_t> &instrs);

#endif