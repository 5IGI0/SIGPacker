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

#ifndef FORMATS_PE_PE_HH
#define FORMATS_PE_PE_HH

#include <cstddef>
#include <cstdint>
#include <vector>

#include "structs.h"

#include "../../structs.hh"
#include "../../AllowList.hh"

typedef struct {
    bool                    is_PE32;
    uint8_t                 *start;
    size_t                  length;
    size_t                  symbol_count;
    PIMAGE_SYMBOL           symbols;
    size_t                  section_count;
    PIMAGE_SECTION_HEADER   sections;
    uint8_t                 **section_data;
    char                    *strings;
    union {
        PIMAGE_NT_HEADERS32 b32;
        PIMAGE_NT_HEADERS64 b64;
    } nt_hdr;
} pe_file_t;

typedef struct {
    char                    *name;
    uintptr_t               vaddr;
    size_t                  offset;
    size_t                  size;
    bool                    is_IAT_stub;
    bool                    must_poly;
    PIMAGE_SYMBOL           raw_symbol;
    PIMAGE_SECTION_HEADER   section;
} symbol_entry_t;

void handle_pe(runtime_t &runtime);
bool parse_pe(runtime_t &runtime, pe_file_t &file);
bool pe_polyform_functions(pe_file_t &pe, std::vector<symbol_entry_t> functions);
bool pe_is_IATStub(pe_file_t &pe, symbol_entry_t entry);
char *pe_ptr_from_rva(pe_file_t &pe, uintptr_t rva);
void pe_build(pe_file_t &pe, runtime_t &runtime);
int pe_hide_imports(runtime_t &runtime, pe_file_t &pe);
PIMAGE_SECTION_HEADER pe_get_section(pe_file_t &pe, char const *name);
uintptr_t pe_append_section(pe_file_t &pe, char const *name, unsigned char const *data, size_t datalen);
std::vector<symbol_entry_t> pe_list_functions(pe_file_t &pe, AllowList &allowed);
void pe_free_function_list(std::vector<symbol_entry_t> &list);
void free_pe(pe_file_t &pe);
void pe_gen_polylist(runtime_t &runtime, AllowList &polylist);
uint32_t pe_header_checksum(uint32_t *base, size_t size);

#define PE_HDR(pe, attr) (pe.is_PE32 ? pe.nt_hdr.b32->OptionalHeader.attr : pe.nt_hdr.b64->OptionalHeader.attr)

#endif