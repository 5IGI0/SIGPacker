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

#ifndef ARCH_X86_REGISTERS_H
#define ARCH_X86_REGISTERS_H

enum x86registers {
    REG_NONE, // keep it first
    REG_RAX, REG_RBX,
    REG_RCX, REG_RDX,
    REG_RSI, REG_RDI,
    REG_RBP, REG_RSP,
    REG_RIP, REG_FLAGS,
    REG_R8,  REG_R9,
    REG_R10, REG_R11,
    REG_R12, REG_R13,
    REG_R14, REG_R15,
    REG_COUNT};

#ifdef __cplusplus
extern "C" {
#endif
// convert sized registers (ZYDIS_REGISTER_AL) to unsized register (REG_RAX)
int x86_get_unsized_register(int reg);
int x86_get_64_register(int reg);
int x86_get_32_register(int reg);
int x86_get_register_by_size(int reg, int size);
#ifdef __cplusplus
}
#endif
#endif