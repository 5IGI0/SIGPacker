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

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

#include "pe.hh"

#include "../../arch/x86/polymorph.hh"
#include "structs.h"

bool pe_polyform_functions(pe_file_t &pe, std::vector<symbol_entry_t> functions) {
    for (size_t i = 0; i < functions.size(); i++) {
        if (functions[i].raw_symbol->Type != 0x20 || functions[i].is_IAT_stub || !functions[i].must_poly) {continue;}
        uint8_t *func_code = pe.start + functions[i].offset;

        polyform_x86(func_code, functions[i].size, pe.is_PE32 ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_64);
    }
    
    return true;
}