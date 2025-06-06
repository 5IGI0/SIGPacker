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
#include <cstdio>
#include <cstring>
#include <iostream>

#include "pe.hh"
#include "data_obfs/data_obfs.hh"

#include "../../structs.hh"

void handle_pe(runtime_t &runtime) {
    pe_file_t pe;
    std::vector<symbol_entry_t> functions;
    AllowList polylist;

    if (!parse_pe(runtime, pe))                 return;
    pe_gen_polylist(runtime, polylist);
    functions = pe_list_functions(pe, polylist);
    if (functions.size() == 0) {
        std::cerr << "Error: stripped binary." << std::endl;
        return;
    }
    
    if (!pe_obfusc_data(pe, functions)) return;
    if (!pe_polyform_functions(pe, functions)) return;

    if (runtime.hide_imports.size())
        pe_hide_imports(runtime, pe);

    pe_free_function_list(functions);
    pe_build(pe, runtime);
    free_pe(pe);
}