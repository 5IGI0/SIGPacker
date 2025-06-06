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

#include <cstring>
#include <iostream>

#include "data_obfs.hh"

#include "../../../arch/x86/addr_references.hh"
#include "../../../third/zydis/Zydis.h"


static inline
bool comp_range(encrypt_range_t const &a, encrypt_range_t const &b) {
    return a.start < b.start;
}

void pe_obfs_get_ranges(pe_file_t &pe, std::vector<symbol_entry_t> functions, std::vector<encrypt_range_t> &ranges) {
    std::vector<uint64_t>        refs;

    for (size_t i = 0; i < functions.size(); i++) {
        if (functions[i].raw_symbol->Type != 0x20 || functions[i].is_IAT_stub) {continue;}
        x86_list_references(
            pe.start + functions[i].offset,
            functions[i].size,
            pe.is_PE32 ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_64,
            functions[i].vaddr, refs);

        for (auto &ref : refs) {
            // std::cout << std::hex << ref << std::endl;
            if (!pe.is_PE32 || ref >= PE_HDR(pe, ImageBase)) {
                ranges.push_back(encrypt_range_t{ // if it is 32bits, then it is vaddr and we convert it to rva
                    .start = ref - (pe.is_PE32 ? PE_HDR(pe, ImageBase) : 0), .must_be_encrypted = functions[i].must_poly});
            }
        }
    }

    {
        // try to not break the linker
        PIMAGE_DATA_DIRECTORY datadirs = PE_HDR(pe, DataDirectory);
        size_t                num_dir  = PE_HDR(pe, NumberOfRvaAndSizes);
        
        for (size_t i = 0; i < num_dir; i++) {
            if (datadirs[i].VirtualAddress && datadirs[i].Size) {
                ranges.push_back(encrypt_range_t{
                    .start = datadirs[i].VirtualAddress,
                    .must_be_encrypted = false});
            }
        }
    }

    {
        // avoid to encrypt refptrs
        // (if the decrypt payload is executed before initalisation it shouldn't break anything
        // BUT, i guess, it might help to make YARA rules.)
        for (size_t i = 0; i < pe.symbol_count; i++) {
            // .refptr. -> can't be inline-stored
            if (pe.symbols[i].N.Name.Short == 0 && memcmp(".refptr.", pe.strings + pe.symbols[i].N.Name.Long, 8) == 0) {
                ranges.push_back(encrypt_range_t{
                .start = *(uint64_t*)(pe.start + pe.sections[pe.symbols[i].SectionNumber-1].PointerToRawData + pe.symbols[i].Value) - PE_HDR(pe, ImageBase),
                .must_be_encrypted = false});
            }
        }
    }

    if (ranges.size()) ranges[0].start = 0;

    std::sort(ranges.begin(), ranges.end(), comp_range);

    for (auto it = ranges.begin(); it != ranges.end(); ++it) {
        auto nit = std::next(it);

        while (
            nit != ranges.end() && (
                // if the next range must also be encrypted, then merge them
                nit->must_be_encrypted == it->must_be_encrypted ||
                // if the next range is on the same addr but shouldn't be encrypted
                // then a it must share the same buffer, encrypt it to be sure.
                nit->start == it->start && nit->must_be_encrypted == false
            )) {
            if (nit->start == it->start && it->must_be_encrypted && nit->must_be_encrypted == false)
                std::cerr << "Warning: a buffer is shared with an non-polyform function (" << std::hex << it->start << ")" << std::endl;
            ranges.erase(nit);
            nit = std::next(it);
        }

        if (nit == ranges.end()) 
            it->length = -1;
        else
            it->length = nit->start - it->start;

        if (it->length == 0) {
            // must be followed an _must encrypt_ range that points to the same area
            // remove this one
            // TODO: warning
            it = ranges.erase(it);
            if (it != ranges.begin()) it = std::prev(it);
        }
    }
}