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

#include <clocale>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "formats/pe/pe.hh"

#include "arch/x86/polymorph.hh"

#include "third/zydis/Zydis.h"

#include "utils.h"
#include "structs.hh"

int main(int argc, char **argv) {
    runtime_t runtime = {0};

    setlocale(LC_ALL, "C");

    if (parse_opts(argc, argv, &runtime) < 0)
        return 1;

    runtime.input_content = load_file(runtime.input_path, &runtime.input_size);
    if (runtime.input_content == NULL) {
        perror(runtime.input_path);
        return 1;
    }

    std::srand(std::time(NULL));

    if (runtime.input_size > 2 && memcmp("MZ", runtime.input_content, 2) == 0) {
        handle_pe(runtime);
    } else {
        std::cerr << "unknown format" << std::endl;
    }

    free(runtime.input_content);
}