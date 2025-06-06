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
#include <cstdint>

#include "pe.hh"

#include "../../third/zydis/Zydis.h"

// TODO: maybe just check if the symbol's name is in the idata?
bool pe_is_IATStub(pe_file_t &pe, symbol_entry_t entry) {
    ZydisDisassembledInstruction instr;

    assert(ZYAN_SUCCESS(ZydisDisassembleIntel( // TODO: check error
        /* machine_mode:    */ (ZydisMachineMode)(pe.is_PE32 ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_64),
        /* runtime_address: */ entry.vaddr,
        /* buffer:          */ pe.start + entry.offset,
        /* length:          */ entry.size,
        /* instruction:     */ &instr
    )));

    // TODO: tested for mingw x86_64 / i386
    if (
        instr.info.mnemonic              != ZYDIS_MNEMONIC_JMP        ||
        instr.info.operand_count_visible != 1                         ||
        instr.operands[0].type           != ZYDIS_OPERAND_TYPE_MEMORY ||
        (
            instr.operands[0].mem.base       != ZYDIS_REGISTER_RIP  &&
            instr.operands[0].mem.base       != ZYDIS_REGISTER_NONE)  ||
        instr.operands[0].mem.index      != ZYDIS_REGISTER_NONE)
        return false;

    uint64_t target_addr = instr.operands[0].mem.disp.value;

    if (instr.operands[0].mem.base == ZYDIS_REGISTER_RIP)
        target_addr += entry.vaddr + instr.info.length;

    uint64_t IAT_addr      = PE_HDR(pe, DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
    uint64_t IAT_size      = PE_HDR(pe, DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);

    // no RIP -> not relative -> rva + imagebase
    if (instr.operands[0].mem.base == ZYDIS_REGISTER_NONE)
        IAT_addr += PE_HDR(pe, ImageBase);

    return (target_addr >= IAT_addr && target_addr < IAT_addr+IAT_size);
}