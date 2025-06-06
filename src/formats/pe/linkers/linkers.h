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

#ifndef FORMATS_PE_LINKERS_LINKERS_H
#define FORMATS_PE_LINKERS_LINKERS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct {
    uint32_t    dll_name;
    uint32_t    func_name;
    uint64_t    IAT_addr;
} hidden_import_64_t;

typedef struct {
    uint32_t    dll_name;
    uint32_t    func_name;
    uint32_t    IAT_addr;
} hidden_import_32_t;

extern unsigned char    pe_x86_64_linker[];
extern unsigned int     pe_x86_64_linker_len;
extern unsigned int     pe_x86_64_linker_entry;
extern unsigned char    pe_x86_linker[];
extern unsigned int     pe_x86_linker_len;
extern unsigned int     pe_x86_linker_entry;
#ifdef __cplusplus
}
#endif

#endif