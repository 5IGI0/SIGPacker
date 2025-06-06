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

#include <cstdlib>
#include <vector>
#include <algorithm>

#include <cstddef>
#include <cassert>
#include <cstring>

#include "data_obfs.hh"

#include "../pe.hh"
#include "../structs.h"

#include <x86intrin.h>

static inline
void pe_fill_obfs_ctx(data_obfs_ctx_t &ctx) {
    ctx.op_count = (rand() % (sizeof(ctx.ops)/sizeof(ctx.ops[0]))) + 1;

    auto &ops = ctx.ops;

    for (size_t i = 0; i < ctx.op_count; i++) {
        ops[i].key     = rand();

        while (1) {
            ops[i].op_type = rand() % OBFS_OP_TYPE_COUNT;
            if (i == 0)
                break; // no need to check anything for the first element

            if ( // if + and - follows, it doesn't make any sense (since +5 -3 can just be +2)
                (ops[i].op_type == OBFS_OP_TYPE_ADD || ops[i].op_type == OBFS_OP_TYPE_SUB) &&
                (ops[i-1].op_type == OBFS_OP_TYPE_ADD || ops[i-1].op_type == OBFS_OP_TYPE_SUB)
            )   continue;

            if (ops[i].op_type == OBFS_OP_TYPE_XOR && ops[i-1].op_type == OBFS_OP_TYPE_XOR)
                continue; // i believe 2 xor can be turned into a single one

            if (
                (ops[i].op_type == OBFS_OP_TYPE_ROL || ops[i].op_type == OBFS_OP_TYPE_ROR) &&
                (ops[i-1].op_type == OBFS_OP_TYPE_ROL || ops[i-1].op_type == OBFS_OP_TYPE_ROR)
            ) continue;

            break;
        }

        if (ops[i].op_type == OBFS_OP_TYPE_ROL || ops[i].op_type == OBFS_OP_TYPE_ROR)
            ctx.ops[i].key = (rand()%15) + 1; // if it is ro(l/r), it doesn't make sense to rotate 0x48548585 bits.
    }
}

static inline
void pe_encrypt(pe_file_t &pe, data_obfs_ctx_t &ctx, encrypt_range_t range, uint8_t *data) {
    memset(&ctx, 0, sizeof(ctx));

    ctx.vaddr = range.start + PE_HDR(pe, ImageBase);
    ctx.len = range.length;

    pe_fill_obfs_ctx(ctx);

    assert((range.start % 4) == 0);
    assert((range.length % 4) == 0);

    for (size_t i = 0; i < range.length/4; i++) {
        uint32_t tmp = ((uint32_t *)data)[i];
        for (ssize_t j = ctx.op_count-1; j >= 0; j--) {
            switch (ctx.ops[j].op_type) {
                // NOTE: we encrypt so we have to do the opposite operations
                case OBFS_OP_TYPE_ADD: tmp -= ctx.ops[j].key;            break;
                case OBFS_OP_TYPE_SUB: tmp += ctx.ops[j].key;            break;
                case OBFS_OP_TYPE_XOR: tmp ^= ctx.ops[j].key;            break;
                case OBFS_OP_TYPE_ROL: tmp = _rotr(tmp, ctx.ops[j].key); break;
                case OBFS_OP_TYPE_ROR: tmp = _rotl(tmp, ctx.ops[j].key); break;
            }
        }
        ((uint32_t *)data)[i] = tmp;
    }
}

static inline
void pe_obfs_encrypt_ranges(pe_file_t &pe, std::vector<encrypt_range_t> &ranges, std::vector<data_obfs_ctx_t> &contexts) {
    for (auto &range : ranges) {
        uint8_t *ptr = (uint8_t *)pe_ptr_from_rva(pe, range.start);
        
        data_obfs_ctx_t ctx;
        pe_encrypt(pe, ctx, range, ptr);
        contexts.push_back(ctx);
    }
}

bool pe_obfusc_data(pe_file_t &pe, std::vector<symbol_entry_t> functions) {
    std::vector<encrypt_range_t> ranges;
    std::vector<encrypt_range_t> clean_ranges;

    pe_obfs_get_ranges(pe, functions, ranges);

    for (size_t i = 0; i < pe.section_count; i++) {
        uint64_t rva       = pe.sections[i].VirtualAddress;
        uint8_t  *secdt    = pe.section_data[i];
        size_t   cur_range = 0;

        if (memcmp(pe.sections[i].Name, ".rdata", 6) && memcmp(pe.sections[i].Name, ".data", 5))
            continue;

        for (size_t j = 0; j < ranges.size(); j++) {
            if ((!ranges[j].must_be_encrypted)|| rva > (ranges[j].start + ranges[j].length))
                continue;
            if (ranges[j].start > (rva + pe.sections[i].SizeOfRawData))
                break;

            pe.sections[i].Characteristics |= IMAGE_SCN_MEM_WRITE; // TODO: use virtualprotect
            uint64_t start = std::max(rva, ranges[j].start);

            clean_ranges.push_back(encrypt_range_t{
                .start  = start,
                .length = std::min(
                    (uint64_t)pe.sections[i].SizeOfRawData - (start - pe.sections[i].VirtualAddress),
                    ranges[j].start + ranges[j].length - start),
                .must_be_encrypted = true,
            });
        }
    }

    std::vector<data_obfs_ctx_t> contexts;
    pe_obfs_encrypt_ranges(pe, clean_ranges, contexts);
    pe_add_dec_payloads(pe, contexts);

    return true;
}