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

#include "../pe.hh"

#include <cassert>
#include <cctype>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string.h>
#include <vector>
#include <string>

template<typename IMAGE_THUNK_DATA>
std::vector<std::string> pe_load_import_whitelist(runtime_t &runtime, pe_file_t &pe, char const *dll, IMAGE_THUNK_DATA *thunks) {
    std::vector<std::string> ret;
    char lower_dll[strlen(dll)];

    strcpy(lower_dll, dll);
    for (size_t i = 0; lower_dll[i]; i++)
        lower_dll[i] = tolower(lower_dll[i]);

    try {
        std::ifstream list(std::string("data/import_whitelists/") + lower_dll + ".txt");
        
        std::string line;
        while (std::getline(list, line)) {
            if (line.length() == 0 || line[0] == ';')
                continue;

            bool suc = true;
            for (size_t i = 0; i < runtime.hide_imports.size(); i++) {
                if (line == runtime.hide_imports[i]) {
                    suc = false;
                    break;
                }
            }
            if (!suc) continue;

            for (size_t i = 0;; i++) {
                char *import_name = (char *)pe_ptr_from_rva(pe, thunks[i].u1.ForwarderString);
                if (import_name == NULL)
                    break;
                if (line == (import_name+2)) {
                    suc = false;
                    break;
                }
            }
            if (!suc) continue;

            ret.push_back(line);
        }
    } catch (std::exception e) {
        std::cerr << "Warning: " << e.what() << std::endl;
    }

    return ret;
}

template<typename hidden_import_t, typename IMAGE_THUNK_DATA>
void pe_dummify_imports(runtime_t &runtime, pe_file_t &pe, hidden_import_t *hidden_imports) {
    PIMAGE_SECTION_HEADER idata = pe_get_section(pe, ".idata");
    PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)(pe.start + idata->PointerToRawData);
    std::vector<std::string> whitelist;

    for (size_t j = 0; 1; j++) {
        char *dll_name = pe_ptr_from_rva(pe, imports[j].Name);
        if (dll_name == NULL) break;

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

            PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)pe_ptr_from_rva(pe, view_thunk[k].u1.ForwarderString);
            typeof(hidden_imports->IAT_addr) addr = (typeof(hidden_imports->IAT_addr))(imports[j].FirstThunk + (sizeof(IMAGE_THUNK_DATA*) * k) + PE_HDR(pe, ImageBase));

            for (size_t y = 0; y < runtime.hide_imports.size(); y++) {
                if (hidden_imports[y].IAT_addr == addr) {
                    uint16_t ordinal = import_name->Hint;
                    memset(import_name, 0, sizeof(*import_name)+strlen((char const *)import_name->Name)); // TODO: regenerate the whole string table
                    // TODO: find a good ordinal value
                    uint16_t name_addr = pe_append_section(pe, ".idata", (unsigned char *)&ordinal, 2);

                    if (whitelist.empty()) {
                        whitelist = pe_load_import_whitelist(runtime, pe, dll_name, view_thunk);
                        assert(whitelist.size());
                    }

                    int replacement_id = rand()%whitelist.size();
                    auto replacement = whitelist[replacement_id];
                    whitelist.erase(std::next(whitelist.begin(), replacement_id));

                    assert(pe_append_section(pe, ".idata", (unsigned char *)replacement.c_str(), replacement.size()+1));

                    // the new data to the section has been added, so we need to recompute it
                    view_thunk  = (IMAGE_THUNK_DATA*)pe_ptr_from_rva(pe, imports[j].OriginalFirstThunk);
                    set_thunk   = (IMAGE_THUNK_DATA*)pe_ptr_from_rva(pe, imports[j].FirstThunk);
                    view_thunk[k].u1.ForwarderString = name_addr;
                }
            }
        }

        whitelist.clear();
    }

}