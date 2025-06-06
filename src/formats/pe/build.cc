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
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

unsigned char dos_stub[] = {
0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,  // |MZ..............|
0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // |........@.......|
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // |................|
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  // |................|
0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,  // |........!..L.!Th|
0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,  // |is program canno|
0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,  // |t be run in DOS |
0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // |mode....$.......|

/*
TODO LIST:
[ ] random (plausible) TimeDateStamp
[ ] memset/remove symbol table (and string table) in sections
    it is supposed to be in debug sections (which are dropped) but who knows /shrug
[ ] remove relocations
[X] compute checksum
[ ] fix directories pointing to removed sections
*/

#define USE_ROUNDER(val, rounder) ((((val)-1) | rounder)+1)

static size_t drop_unwanted_sections(
    pe_file_t &pe,
    int       *io_section_map
) {
    size_t  output_idx = 0;

    for (size_t i = 0; i < pe.section_count; i++) {
        // if the section name starts with .debug, skip it.
        char *name = (char *)pe.sections[i].Name;

        if (pe.sections[i].Name[0] == '/')
            name = pe.strings + atoi((char *)(&pe.sections[i].Name)+1);

        if (
            memcmp(".debug", name, 6) == 0 ||
            memcmp(".reloc", name, 6) == 0 ||
            memcmp(".pdata", name, 6) == 0 ||
            memcmp(".xdata", name, 6) == 0)
            continue;

        io_section_map[output_idx] = i;
        output_idx++;
    }

    return output_idx;
}

static void prepare_section_table(
    pe_file_t               &pe,
    PIMAGE_SECTION_HEADER   infile_sections_tbl,
    int                     *io_section_map,
    size_t                  after,
    size_t                  rounder, size_t sec_count) {

    for (size_t i = 0; i < sec_count; i++) {
        after = USE_ROUNDER(after, rounder);

        PIMAGE_SECTION_HEADER original_sec = &pe.sections[io_section_map[i]];
        infile_sections_tbl[i] = *original_sec;

        // truncate section name if too large
        if (original_sec->Name[0] == '/') {
            strncpy(
                (char *)infile_sections_tbl[i].Name,
                pe.strings + atoi((char *)(&original_sec->Name)+1),
                8);
        }

        if (infile_sections_tbl[i].SizeOfRawData) {
            infile_sections_tbl[i].PointerToRawData = after;
        } else {
            infile_sections_tbl[i].PointerToRawData = 0;
        }

        after += original_sec->SizeOfRawData;
    }
}

template<typename IMAGE_NT_HEADERS>
void pe_update_and_put_headers(IMAGE_NT_HEADERS &original_hdr, uint8_t *dst, size_t sec_count) {
    auto hdr = original_hdr;

    hdr.FileHeader.Characteristics      |= IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_RELOCS_STRIPPED;
    hdr.FileHeader.NumberOfSymbols      = 0;
    hdr.FileHeader.PointerToSymbolTable = 0;
    hdr.FileHeader.TimeDateStamp        = time(NULL);
    hdr.FileHeader.NumberOfSections     = sec_count;

    hdr.OptionalHeader.CheckSum = 0;

    hdr.OptionalHeader.DataDirectory[IMAGE_FILE_BASE_RELOCATION_TABLE].Size = 0;
    hdr.OptionalHeader.DataDirectory[IMAGE_FILE_BASE_RELOCATION_TABLE].VirtualAddress = 0;
    hdr.OptionalHeader.DataDirectory[IMAGE_FILE_EXCEPTION_DIRECTORY].Size = 0;
    hdr.OptionalHeader.DataDirectory[IMAGE_FILE_EXCEPTION_DIRECTORY].VirtualAddress = 0;

    memcpy(dst, &hdr, sizeof(hdr));
}

void pe_build(pe_file_t &pe, runtime_t &runtime) {
    uint8_t *pe_buff       = NULL;
    size_t  pe_size        = 0;
    size_t  sec_tbl_offset = 0;
    size_t  rounder        = 0xFFF;

    /* 1. eliminate unwanted sections */
    int    io_section_map[pe.section_count];
    size_t sec_count = drop_unwanted_sections(pe, io_section_map);

    /* 2. compute headers' size */
    pe_size       += sizeof(dos_stub);
    pe_size       += pe.is_PE32 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
    sec_tbl_offset = pe_size;
    pe_size       += sizeof(IMAGE_SECTION_HEADER) * sec_count;

    /* 3. find offsets for sections (prepare section table) */
    rounder = PE_HDR(pe, FileAlignment)-1;
    IMAGE_SECTION_HEADER infile_sections_tbl[sec_count];
    memset(infile_sections_tbl, 0, sizeof(infile_sections_tbl));
    prepare_section_table(pe, infile_sections_tbl, io_section_map, pe_size, rounder, sec_count);

    /* 4. compute final PE size & alloc */
    pe_size = (infile_sections_tbl[sec_count-1].PointerToRawData +
               infile_sections_tbl[sec_count-1].SizeOfRawData);
    // position and size are aligned on x (and x > 4 theoretically),
    // so the final size is supposed to be a multiple of 4
    // which might cause issue for checksum computation if not true)
    assert((pe_size%4) == 0);
    assert((pe_buff = (uint8_t *)calloc(1, pe_size)));

    /* 5. put DOS stub */
    memcpy(pe_buff, dos_stub, sizeof(dos_stub));

    /* 6. update PE header and put it */
    if (pe.is_PE32) pe_update_and_put_headers(*pe.nt_hdr.b32, pe_buff+sizeof(dos_stub), sec_count);
    else            pe_update_and_put_headers(*pe.nt_hdr.b64, pe_buff+sizeof(dos_stub), sec_count);

    /* 7. flush sections */
    memcpy(pe_buff+sec_tbl_offset, infile_sections_tbl, sizeof(infile_sections_tbl));
    for (size_t i = 0; i < sec_count; i++) {
        if (infile_sections_tbl[i].PointerToRawData) {
            memcpy(
                pe_buff+infile_sections_tbl[i].PointerToRawData,
                pe.section_data[io_section_map[i]],
                infile_sections_tbl[i].SizeOfRawData);
        }
    }

    /* 8. compute checksum */
    pe_header_checksum((uint32_t *)pe_buff, pe_size);

    /* and finally write it into a file. */
    FILE *fp = fopen(runtime.output_path, "wb");
    assert(fp);
    fwrite(pe_buff, 1, pe_size, fp);
    fclose(fp);
    free(pe_buff);
}