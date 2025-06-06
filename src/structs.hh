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

#ifndef STRUCT_HH
#define STRUCT_HH

#include <stddef.h>
#include <stdint.h>
#include <vector>

#include "AllowList.hh"

typedef struct {
    char                *input_path;
    uint8_t             *input_content;
    size_t              input_size;
    char                *output_path;
    std::vector<char *> hide_imports;
    bool                only_explicit_polyform;
    bool                polyform_all;
    AllowList           user_polylist;
} runtime_t;

int parse_opts(int argc, char **argv, runtime_t *runtime);

#endif