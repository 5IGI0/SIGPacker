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

#ifndef FMT_PE_DATA_OBFS_DATA_OBFS_HH
#define FMT_PE_DATA_OBFS_DATA_OBFS_HH

#include <cstdint>
#include <vector>

#include "../pe.hh"

typedef struct {
    uint64_t start;
    uint64_t length;
    bool     must_be_encrypted;
} encrypt_range_t;

enum {
    OBFS_OP_TYPE_SUB,
    OBFS_OP_TYPE_XOR,
    OBFS_OP_TYPE_ADD,
    OBFS_OP_TYPE_ROL,
    OBFS_OP_TYPE_ROR,
    OBFS_OP_TYPE_COUNT
};

typedef struct {
    uint8_t  op_type;
    uint32_t key;
} data_obfs_op_t;

typedef struct {
    uint64_t vaddr;
    size_t   len;
    uint8_t  op_count;
    data_obfs_op_t ops[5];
} data_obfs_ctx_t;

void pe_obfs_get_ranges(pe_file_t &pe, std::vector<symbol_entry_t> functions, std::vector<encrypt_range_t> &ranges);
bool pe_obfusc_data(pe_file_t &pe, std::vector<symbol_entry_t> functions);
void pe_add_dec_payloads(pe_file_t &pe, std::vector<data_obfs_ctx_t> &contexts);

#endif