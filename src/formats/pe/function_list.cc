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

#include "pe.hh"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

std::vector<symbol_entry_t> pe_list_functions(pe_file_t &pe, AllowList &allowed) {
    std::vector<symbol_entry_t> functions;

    if (pe.symbols == NULL || pe.symbol_count == 0)
        return functions;

    /* find all functions */
    for (size_t i = 0; i < pe.symbol_count; i++) {
        if ( // TODO: find all classes that use offset in sections
            (pe.symbols[i].StorageClass != IMAGE_SYM_CLASS_EXTERNAL && pe.symbols[i].StorageClass != IMAGE_SYM_CLASS_STATIC)
            && pe.symbols[i].SectionNumber > 0)
            continue;

        PIMAGE_SECTION_HEADER sec = &pe.sections[pe.symbols[i].SectionNumber-1];
        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SCN_MEM_EXECUTE)
            continue; /* keep only symbols in executable sections */

        symbol_entry_t symbol = {0};
        symbol.raw_symbol = &pe.symbols[i];
        symbol.vaddr = sec->VirtualAddress + pe.symbols[i].Value;
        symbol.offset = sec->PointerToRawData + pe.symbols[i].Value;
        symbol.section = sec;
        
        if (pe.symbols[i].N.Name.Short == 0) {
            symbol.name = (char *)malloc(strlen(pe.strings + pe.symbols[i].N.Name.Long) + 1);
            strcpy(symbol.name, pe.strings + pe.symbols[i].N.Name.Long);
        } else {
            symbol.name = (char *)malloc(9);
            memcpy(symbol.name, &pe.symbols[i].N.Name, 8);
            symbol.name[8] = 0;
        }

        if (symbol.raw_symbol->Type == 0x20) {
            if (!pe.is_PE32)
                symbol.must_poly = allowed.allowed(symbol.name);
            else {
                // for the same command to work in 32 and 64, ignore the leading underscore
                // (mandatory according to the windows ABI)
                // TODO: --no-implicit-leading-underscore (to disable it)
                char *name = symbol.name;
                if (name[0] != '_')
                    std::cerr << "Warning: no leading underscore for symbol `" << symbol.name << "` (expected in 32bits)" << std::endl;
                else
                    name++;
                symbol.must_poly = allowed.allowed(name);
            }
        }
        
        functions.push_back(symbol);
    }

    /* compute functions' size */
    for (size_t i = 0; i < functions.size(); i++) {
        functions[i].size = (functions[i].section->VirtualAddress + functions[i].section->SizeOfRawData) - functions[i].vaddr;

        for (size_t j = 0; j < functions.size(); j++) {
            if (functions[j].vaddr != functions[i].vaddr && (functions[j].vaddr - functions[i].vaddr) < functions[i].size)
                functions[i].size = functions[j].vaddr - functions[i].vaddr;
        }
    }

    /* check for IAT stubs */
    for (size_t i = 0; i < functions.size(); i++) {
        if (functions[i].raw_symbol->Type == 0x20)
            functions[i].is_IAT_stub = pe_is_IATStub(pe, functions[i]);
    }

    return functions;
}

void pe_free_function_list(std::vector<symbol_entry_t> &list) {
    for (size_t i = 0; i < list.size(); i++) {
        free(list[i].name);}
    list.clear();
}