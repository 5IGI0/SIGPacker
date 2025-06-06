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

#include <iostream>
#include <vector>

#include "polymorph.hh"

static int find_modifier(std::vector<poly_instr_t> &instrs, size_t start_point, int flag_bit) {
    for (ssize_t i = start_point; i >= 0; i--) {
        if (instrs[i].instruction.info.cpu_flags) {
            if (instrs[i].instruction.info.cpu_flags->modified & flag_bit)
                return i;
        }
    }
    return -1;
}

void x86_group_conditional_ops(std::vector<poly_instr_t> &instrs, int &group_id) {
    /*  the principle is straightforward,
        1. find instructions that access CPU's flags
        2. seek for the last one that modified it
        3. group them */

    for (size_t i = 0; i < instrs.size(); i++) {
        if (instrs[i].instruction.info.cpu_flags) {
            /*  there are 22 cpu flags in the zydis lib,
                from what i see, there is no define for it. */
            for (int flag_id = 0; flag_id < 22; flag_id++) {
                int flag_bit = 1u << flag_id;

                if (instrs[i].instruction.info.cpu_flags->tested & flag_bit) {

                    int ret = find_modifier(instrs, i, flag_bit);

                    if (ret < 0) {
                        std::cerr << "Warning: unable to find modifier for flag " << flag_id << std::endl;
                    } else {
                        group_id++;
                        for (size_t j = ret; j < i+1; j++) {
                            instrs[j].is_conditional = true;
                            instrs[j].group_id = group_id;
                        }
                    }
                    
                    /*  TODO: i don't know if instruction op can test several flags at once
                        if yes, then we should test every flags and group to the farest instruction */
                    break;
                }
            }
        }
    }
}