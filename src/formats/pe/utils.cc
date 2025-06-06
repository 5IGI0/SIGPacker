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
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "pe.hh"
#include "structs.h"

char *pe_ptr_from_rva(pe_file_t &pe, uintptr_t rva) {
    for (size_t i = 0; i < pe.section_count; i++) {
        if (rva >= pe.sections[i].VirtualAddress && rva < pe.sections[i].VirtualAddress+pe.sections[i].SizeOfRawData)
            return (char *)(pe.section_data[i] + (rva - pe.sections[i].VirtualAddress));
    }
    return NULL;
}

PIMAGE_SECTION_HEADER pe_get_section(pe_file_t &pe, char const *name) {
    for (size_t i = 0; i < pe.section_count; i++) {
        if (strcmp((char *)pe.sections[i].Name, name) == 0)
            return &pe.sections[i];
    }
    return NULL;
}

size_t pe_get_free_space(pe_file_t &pe, PIMAGE_SECTION_HEADER sec) {
    uintptr_t next_used_vaddr = ((uintptr_t)-1)>>1;
    uintptr_t end_of_sec      = sec->VirtualAddress + sec->VirtualSize;

    for (size_t j = 0; j < pe.section_count; j++) {
        if (&pe.sections[j] == sec)
            continue;

        uintptr_t vaddr = pe.sections[j].VirtualAddress;
        if (vaddr < next_used_vaddr && vaddr >= end_of_sec)
            next_used_vaddr = vaddr;

        assert(!(vaddr >= sec->VirtualAddress && vaddr < end_of_sec));
    }

    return next_used_vaddr-end_of_sec;
}

uintptr_t pe_append_section(pe_file_t &pe, char const *name, unsigned char const *data, size_t datalen) {
    PIMAGE_SECTION_HEADER sec = pe_get_section(pe, name);

    if (!sec)
        return 0;

    if (pe_get_free_space(pe, sec) < datalen)
        return 0;

    size_t  sec_idx     = ((char *)sec-(char *)pe.sections)/sizeof(IMAGE_SECTION_HEADER);
    uint8_t *ptr        = pe.section_data[sec_idx];
    size_t  offset      = sec->VirtualSize;

    if ((datalen + offset) > sec->SizeOfRawData) {
        // FAUT ROUND ALLOCATED
        sec->SizeOfRawData = ((((size_t)(datalen + offset))-1)|(0x200-1))+1;
        if (ptr >= pe.start && ptr < (pe.start + pe.length)) {
            ptr = (uint8_t *)malloc(sec->SizeOfRawData);
            memcpy(ptr, pe.section_data[sec_idx], offset);
            pe.section_data[sec_idx] = ptr;
        } else {
            ptr = (uint8_t *)realloc(ptr, sec->SizeOfRawData);
            pe.section_data[sec_idx] = ptr;
        }
    }

    memcpy(ptr + offset, data, datalen);
    sec->VirtualSize = offset + datalen;
    return sec->VirtualAddress + offset;
}