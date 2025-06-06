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
#include <cstdlib>
#include <cstdint>

#include "structs.h"

uint32_t pe_header_checksum(uint32_t *base, size_t size) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS32 nt;
    uint32_t *ptr;
    uint32_t sum = 0;
    size_t i;

    assert(size%4 == 0);

    dos = (PIMAGE_DOS_HEADER)base;
    nt = (PIMAGE_NT_HEADERS32)((uint8_t *)base + dos->e_lfanew);
    ptr = (uint32_t *)&nt->OptionalHeader.CheckSum;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        ptr = &((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.CheckSum;

    *ptr = 0;

    for (i = 0; i < (size/4); i++)
        sum += __builtin_uadd_overflow(base[i],sum,&sum);

    sum = (sum&0xffff) + (sum>>16);
    sum += (sum>>16);
    sum &= 0xffff;

    *ptr = (uint32_t)(sum+size);
    return *ptr;
}
