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

#include "../../third/zydis/Zydis.h"

#include "registers.h"

int x86_get_unsized_register(int reg) {
    switch (reg) {
        case ZYDIS_REGISTER_NONE:
            return REG_NONE;

        case  ZYDIS_REGISTER_AL:
        case  ZYDIS_REGISTER_AH:
        case  ZYDIS_REGISTER_AX:
        case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX:
            return REG_RAX;
        
        case  ZYDIS_REGISTER_BL:
        case  ZYDIS_REGISTER_BH:
        case  ZYDIS_REGISTER_BX:
        case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_RBX:
            return REG_RBX;
        
        case  ZYDIS_REGISTER_CL:
        case  ZYDIS_REGISTER_CH:
        case  ZYDIS_REGISTER_CX:
        case ZYDIS_REGISTER_ECX:
        case ZYDIS_REGISTER_RCX:
            return REG_RCX;
        
        case  ZYDIS_REGISTER_DL:
        case  ZYDIS_REGISTER_DH:
        case  ZYDIS_REGISTER_DX:
        case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_RDX:
            return REG_RDX;
        
        case  ZYDIS_REGISTER_SPL:
        case  ZYDIS_REGISTER_SP:
        case ZYDIS_REGISTER_ESP:
        case ZYDIS_REGISTER_RSP:
            return REG_RSP;
        
        case  ZYDIS_REGISTER_BPL:
        case  ZYDIS_REGISTER_BP:
        case ZYDIS_REGISTER_EBP:
        case ZYDIS_REGISTER_RBP:
            return REG_RBP;
        
        case  ZYDIS_REGISTER_DIL:
        case  ZYDIS_REGISTER_DI:
        case ZYDIS_REGISTER_EDI:
        case ZYDIS_REGISTER_RDI:
            return REG_RDI;
        
        case  ZYDIS_REGISTER_SIL:
        case  ZYDIS_REGISTER_SI:
        case ZYDIS_REGISTER_ESI:
        case ZYDIS_REGISTER_RSI:
            return REG_RSI;

        case ZYDIS_REGISTER_R8B:
        case ZYDIS_REGISTER_R8W:
        case ZYDIS_REGISTER_R8D:
        case ZYDIS_REGISTER_R8:
                return REG_R8;

        case ZYDIS_REGISTER_R9B:
        case ZYDIS_REGISTER_R9W:
        case ZYDIS_REGISTER_R9D:
        case ZYDIS_REGISTER_R9:
                return REG_R9;

        case ZYDIS_REGISTER_R10B:
        case ZYDIS_REGISTER_R10W:
        case ZYDIS_REGISTER_R10D:
        case ZYDIS_REGISTER_R10:
                return REG_R10;

        case ZYDIS_REGISTER_R11B:
        case ZYDIS_REGISTER_R11W:
        case ZYDIS_REGISTER_R11D:
        case ZYDIS_REGISTER_R11:
                return REG_R11;

        case ZYDIS_REGISTER_R12B:
        case ZYDIS_REGISTER_R12W:
        case ZYDIS_REGISTER_R12D:
        case ZYDIS_REGISTER_R12:
                return REG_R12;

        case ZYDIS_REGISTER_R13B:
        case ZYDIS_REGISTER_R13W:
        case ZYDIS_REGISTER_R13D:
        case ZYDIS_REGISTER_R13:
                return REG_R13;

        case ZYDIS_REGISTER_R14B:
        case ZYDIS_REGISTER_R14W:
        case ZYDIS_REGISTER_R14D:
        case ZYDIS_REGISTER_R14:
                return REG_R14;

        case ZYDIS_REGISTER_R15B:
        case ZYDIS_REGISTER_R15W:
        case ZYDIS_REGISTER_R15D:
        case ZYDIS_REGISTER_R15:
                return REG_R15;

        case ZYDIS_REGISTER_RIP:
        case ZYDIS_REGISTER_EIP:
        case ZYDIS_REGISTER_IP:
                return REG_RIP;
        
        case ZYDIS_REGISTER_FLAGS:
        case ZYDIS_REGISTER_EFLAGS:
        case ZYDIS_REGISTER_RFLAGS:
                return REG_FLAGS;

        default:
            return -1;
    }
}

int x86_get_64_register(int reg) {
    switch (reg) {
        case REG_RAX:   return ZYDIS_REGISTER_RAX;
        case REG_RBX:   return ZYDIS_REGISTER_RBX;
        case REG_RCX:   return ZYDIS_REGISTER_RCX;
        case REG_RDX:   return ZYDIS_REGISTER_RDX;
        case REG_RSI:   return ZYDIS_REGISTER_RSI;
        case REG_RDI:   return ZYDIS_REGISTER_RDI;
        case REG_RBP:   return ZYDIS_REGISTER_RBP;
        case REG_RSP:   return ZYDIS_REGISTER_RSP;
        case REG_R8:    return ZYDIS_REGISTER_R8;
        case REG_R9:    return ZYDIS_REGISTER_R9;
        case REG_R10:   return ZYDIS_REGISTER_R10;
        case REG_R11:   return ZYDIS_REGISTER_R11;
        case REG_R12:   return ZYDIS_REGISTER_R12;
        case REG_R13:   return ZYDIS_REGISTER_R13;
        case REG_R14:   return ZYDIS_REGISTER_R14;
        case REG_R15:   return ZYDIS_REGISTER_R15;
        case REG_RIP:   return ZYDIS_REGISTER_RIP;
        default:        return -1;
    }
}

int x86_get_32_register(int reg) {
    switch (reg) {
        case REG_RAX:   return ZYDIS_REGISTER_EAX;
        case REG_RBX:   return ZYDIS_REGISTER_EBX;
        case REG_RCX:   return ZYDIS_REGISTER_ECX;
        case REG_RDX:   return ZYDIS_REGISTER_EDX;
        case REG_RSI:   return ZYDIS_REGISTER_ESI;
        case REG_RDI:   return ZYDIS_REGISTER_EDI;
        case REG_RBP:   return ZYDIS_REGISTER_EBP;
        case REG_RSP:   return ZYDIS_REGISTER_ESP;
        case REG_RIP:   return ZYDIS_REGISTER_EIP;
        default:        return -1;
    }
}

int x86_get_register_by_size(int reg, int size) {
    switch (size) {
        case 8: return x86_get_64_register(reg);
        case 4: return x86_get_32_register(reg);
        default: return -1;
    }
}