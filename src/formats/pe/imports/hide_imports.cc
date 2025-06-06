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
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>

#include "../pe.hh"

#include "../linkers/linkers.h"
#include "../structs.h"

#include "../../../arch/x86/polymorph.hh"

#include "dummy_imports.hh"

static uint32_t hash_func(const unsigned char *s, size_t len)
{
    uint32_t h = 0, high;
    while (len)
    {
        h = (h << 4) + *s++;
        if ((high = h & 0xF0000000))
            h ^= high >> 24;
        h &= ~high;
        len--;
    }
    return h;
}

static size_t utf8_to_lower_utf16(char *text, char *output) { // TODO: do it properly
    for (size_t i = 0; text[i]; i++) {
        output[i*2] = tolower(text[i]);
        output[i*2+1] = 0;
    }

    return strlen(text)*2;
}

template<typename hidden_import_t, typename IMAGE_THUNK_DATA>
static void pe_fill_hide_import_table(runtime_t &runtime, pe_file_t &pe, hidden_import_t *hidden_imports) {
    char dllname_utf16[256];

    PIMAGE_SECTION_HEADER idata = pe_get_section(pe, ".idata");
    PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)(pe.start + idata->PointerToRawData);

    for (size_t j = 0; 1; j++) {
        char *dll_name = pe_ptr_from_rva(pe, imports[j].Name);
        if (dll_name == NULL) break;


        uint32_t dllname_hash = hash_func((const unsigned char *)dllname_utf16, utf8_to_lower_utf16(dll_name, dllname_utf16));
        IMAGE_THUNK_DATA *view_thunk  = (IMAGE_THUNK_DATA*)pe_ptr_from_rva(pe, imports[j].OriginalFirstThunk);
        IMAGE_THUNK_DATA *set_thunk   = (IMAGE_THUNK_DATA*)pe_ptr_from_rva(pe, imports[j].FirstThunk);

        if (view_thunk == NULL)
            view_thunk = set_thunk;

        for (size_t k = 0; 1; k++) {
            assert((
                view_thunk[k].u1.Ordinal & // TODO: supposed to check if it is an ordinal but idk how to test it
                (((typeof(view_thunk[k].u1.Ordinal))1) << (sizeof(view_thunk[k].u1.Ordinal)*8-1))) == 0);
            
            if (view_thunk[k].u1.ForwarderString == 0)
                break;

            char *import_name = (char *)pe_ptr_from_rva(pe, view_thunk[k].u1.ForwarderString)+2;

            for (size_t y = 0; y < runtime.hide_imports.size(); y++) {
                if (strcmp(import_name, runtime.hide_imports[y]) == 0) {
                    hidden_imports[y].dll_name = dllname_hash;
                    hidden_imports[y].func_name = hash_func((unsigned char const *)import_name, strlen(import_name));
                    hidden_imports[y].IAT_addr = (typeof(hidden_imports[y].IAT_addr))(imports[j].FirstThunk + (sizeof(IMAGE_THUNK_DATA*) * k) + PE_HDR(pe, ImageBase));
                }
            }
        }
    }

    for (size_t i = 0; i < runtime.hide_imports.size(); i++) {
        if (hidden_imports[i].IAT_addr == 0) // TODO: resize import list
            std::cerr << "Warning: unable to find `" << runtime.hide_imports[i] << "` in imports." << std::endl;
    }

    pe_dummify_imports<hidden_import_t, IMAGE_THUNK_DATA>(runtime, pe, hidden_imports);
}

static int pe_hide_imports_x64(runtime_t &runtime, pe_file_t &pe) {
    hidden_import_64_t hidden_imports[runtime.hide_imports.size()];
    memset(hidden_imports, 0, sizeof(hidden_imports));

    pe_fill_hide_import_table<hidden_import_64_t, IMAGE_THUNK_DATA64>(runtime, pe, hidden_imports);

    // at the end of the .text, there are invalid operations.
    // eventually, the beginning is combined with an instruction above it,
    // and the nops are used to separate them so as to have the right code on objdump.
    // assert(pe_append_section(pe, ".text", (uint8_t*)"\x90\x90\x90\x90\x90\x90\x90\x90\x90", 9));

    uintptr_t himps_rva      = pe_append_section(pe, ".rdata", (unsigned char *)hidden_imports, sizeof(hidden_imports[0])*runtime.hide_imports.size());
    uintptr_t linker_rva     = pe_append_section(pe, ".text", pe_x86_64_linker, pe_x86_64_linker_len);
    assert(himps_rva);
    assert(linker_rva);

    /* some variables to make the code more readable */
    uintptr_t linker_entry_rva  = linker_rva + pe_x86_64_linker_entry; 
    uintptr_t bootloader_rva    = linker_rva + pe_x86_64_linker_len;
    uintptr_t call_from_rva     = bootloader_rva + 0x15 + 4;
    uintptr_t jump_from_rva     = bootloader_rva + 0x1A + 4;

    uint8_t bootloader[] =
        "\x48\xb9\x00\x00\x00"  // movabs rcx, 0x0
        "\x00\x00\x00\x00\x00" 
        "\x48\xba\x00\x00\x00"  // movabs rdx, 0x0
        "\x00\x00\x00\x00\x00"
        "\xe8\x2d\x31\x31\x31"  // call   0x31313145
        "\xe9\x41\x45\x45\x45"  // jmp    0x4545455e
        "\xc3";                 // ret 
    
    *(uint64_t *)&bootloader[0x2]  = (himps_rva + PE_HDR(pe, ImageBase));
    *(uint64_t *)&bootloader[0xC]  = runtime.hide_imports.size();
    *(uint32_t *)&bootloader[0x15] = linker_entry_rva - call_from_rva;
    *(uint32_t *)&bootloader[0x1A] = PE_HDR(pe, AddressOfEntryPoint) - jump_from_rva;

    PE_HDR(pe, AddressOfEntryPoint) = bootloader_rva;
    pe_append_section(pe, ".text", bootloader, sizeof(bootloader)-1);

    /* polyform */
    PIMAGE_SECTION_HEADER sec = pe_get_section(pe, ".text");
    size_t offset = sec->VirtualSize;
    size_t  sec_idx = ((char *)sec-(char *)pe.sections)/sizeof(IMAGE_SECTION_HEADER);
    polyform_x86(pe.section_data[sec_idx]+offset, sec->VirtualSize-offset, ZYDIS_MACHINE_MODE_LONG_64);

    return 0;
}

static int pe_hide_imports_x86(runtime_t &runtime, pe_file_t &pe) {
    hidden_import_32_t hidden_imports[runtime.hide_imports.size()];
    memset(hidden_imports, 0, sizeof(hidden_imports));

    pe_fill_hide_import_table<hidden_import_32_t, IMAGE_THUNK_DATA32>(runtime, pe, hidden_imports);

    // at the end of the .text, there are invalid operations.
    // eventually, the beginning is combined with an instruction above it,
    // and the nops are used to separate them so as to have the right code on objdump.
    // assert(pe_append_section(pe, ".text", (uint8_t*)"\x90\x90\x90\x90\x90\x90\x90\x90\x90", 9));

    uintptr_t himps_rva      = pe_append_section(pe, ".rdata", (unsigned char *)hidden_imports, sizeof(hidden_imports[0])*runtime.hide_imports.size());
    uintptr_t linker_rva     = pe_append_section(pe, ".text", pe_x86_linker, pe_x86_linker_len);
    assert(himps_rva);
    assert(linker_rva);

    /* some variables to make the code more readable */
    uintptr_t linker_entry_rva  = linker_rva + pe_x86_linker_entry; 
    uintptr_t bootloader_rva    = linker_rva + pe_x86_linker_len;
    uintptr_t call_from_rva     = bootloader_rva + 11 + 4;
    uintptr_t jump_from_rva     = bootloader_rva + 16 + 4;

    uint8_t bootloader[] =
        "\x68\x00\x00\x00\x00"  // push DWORD 0x0
        "\x68\x00\x00\x00\x00"  // push DWORD 0x0
        "\xe8\x2d\x31\x31\x31"  // call 0x31313145
        "\xe9\x41\x45\x45\x45"  // jmp  0x4545455e
        "\xc3";                 // ret
    
    *(uint32_t *)&bootloader[1]  = runtime.hide_imports.size();
    *(uint32_t *)&bootloader[6]  = (himps_rva + PE_HDR(pe, ImageBase));
    *(uint32_t *)&bootloader[11] = linker_entry_rva - call_from_rva;
    *(uint32_t *)&bootloader[16] = PE_HDR(pe, AddressOfEntryPoint) - jump_from_rva;

    PE_HDR(pe, AddressOfEntryPoint) = bootloader_rva;
    pe_append_section(pe, ".text", bootloader, sizeof(bootloader));

    /* polyform */
    PIMAGE_SECTION_HEADER sec = pe_get_section(pe, ".text");
    size_t offset = sec->VirtualSize;
    size_t  sec_idx = ((char *)sec-(char *)pe.sections)/sizeof(IMAGE_SECTION_HEADER);
    polyform_x86(pe.section_data[sec_idx]+offset, sec->VirtualSize-offset, ZYDIS_MACHINE_MODE_LEGACY_32);

    return 0;
}

int pe_hide_imports(runtime_t &runtime, pe_file_t &pe) {
    if (pe.is_PE32)
        return pe_hide_imports_x86(runtime, pe);
    else
        return pe_hide_imports_x64(runtime, pe);
}