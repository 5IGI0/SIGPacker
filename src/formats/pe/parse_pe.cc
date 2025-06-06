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

#include "defines.h"
#include "pe.hh"
#include "structs.h"

#include "../../structs.hh"
#include <cstdlib>
#include <iostream>

bool parse_pe(runtime_t &runtime, pe_file_t &pe) {
    PIMAGE_DOS_HEADER   dos_hdr     = (PIMAGE_DOS_HEADER)runtime.input_content;
    DWORD               signature   = *(DWORD *)(runtime.input_content + dos_hdr->e_lfanew);
    PIMAGE_FILE_HEADER  hdr         = (PIMAGE_FILE_HEADER)(runtime.input_content + dos_hdr->e_lfanew + 4);

    pe.start      = runtime.input_content;
    pe.length     = runtime.input_size;
    pe.is_PE32    = hdr->Machine == IMAGE_FILE_MACHINE_I386;
    pe.nt_hdr.b64 = (PIMAGE_NT_HEADERS64)(runtime.input_content + dos_hdr->e_lfanew);

    if (signature != PE_SIGNATURE) {
        std::cerr << "Not a PE file." << std::endl;
        return false;
    }

    if (!(hdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        std::cerr << "Not an executable." << std::endl;
        return false;
    }

    if (
        (hdr->Machine != IMAGE_FILE_MACHINE_AMD64   && !pe.is_PE32) ||
        (hdr->Machine != IMAGE_FILE_MACHINE_I386    && pe.is_PE32)) {
        std::cerr << "Architecture not supported" << std::endl;
        return false;
    }
    
    if (
        (hdr->SizeOfOptionalHeader < sizeof(PIMAGE_OPTIONAL_HEADER64) && !pe.is_PE32) ||
        (hdr->SizeOfOptionalHeader < sizeof(PIMAGE_OPTIONAL_HEADER32) && pe.is_PE32)) {
        std::cerr << "Invalid optional header" << std::endl;
        return false;
    }

    if (pe.nt_hdr.b64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && !pe.is_PE32) {
        std::cerr << "Not PE32+ (expected for AMD64 arch)" << std::endl;
        return false;
    }

    if (pe.nt_hdr.b32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && pe.is_PE32) {
        std::cerr << "Not PE32 (expected for i386 arch)" << std::endl;
        return false;
    }

    pe.sections         = IMAGE_FIRST_SECTION(pe.nt_hdr.b32);
    pe.section_count    = pe.nt_hdr.b64->FileHeader.NumberOfSections;
    pe.section_data     = (uint8_t **)malloc(sizeof(uint8_t *) * pe.nt_hdr.b64->FileHeader.NumberOfSections);
    pe.symbols          = (PIMAGE_SYMBOL)(pe.start+pe.nt_hdr.b64->FileHeader.PointerToSymbolTable);
    pe.symbol_count     = pe.nt_hdr.b64->FileHeader.NumberOfSymbols;
    pe.strings          = (char *)&pe.symbols[pe.symbol_count];

    for (size_t i = 0; i < pe.section_count; i++)
        pe.section_data[i] = pe.start + pe.sections[i].PointerToRawData;

    return true;
}

void free_pe(pe_file_t &pe) {
    for (size_t i = 0; i < pe.section_count; i++) {
        if (pe.section_data[i] < pe.start || pe.section_data[i] > pe.start+pe.length)
            free(pe.section_data[i]); // free enlarged sections
    }
    free(pe.section_data);
}