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

#include <cstring>
#include <vector>

#include "../../third/zydis/Zydis.h"

#include "polymorph.hh"
#include "commutative.hh"
#include "registers.h"

/*
TODO LIST
[ ] detect actual commutative operations (such as `sub rax,5` `add rax,8`)
*/

/*
an instruction is not commutative if:
    1. it reads a register/variable that has been written
    2. it writes a register/varible that has been read or written
    3. it writes or read rip
    4. it writes in memory (because it would be too much complex to detect it is has been written/read before)
*/

typedef struct {
    char written_registers[REG_COUNT];
    char read_registers[REG_COUNT];
} commutative_ctx_t;

static void iter_regs(ZydisDisassembledInstruction &instr, void (*func)(ZydisRegister reg, ZydisOperandActions actions, void *data), void *data) {
    for (size_t i = 0; i < instr.info.operand_count; i++) {
        if (instr.operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER)
            func(instr.operands[i].reg.value, instr.operands[i].actions, data);
        else if (instr.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            /* if the memory operand use registers, then they are being read */
            if (instr.operands[i].mem.base != ZYDIS_REGISTER_NONE)
                func(instr.operands[i].mem.base, ZYDIS_OPERAND_ACTION_READ, data);
            if (instr.operands[i].mem.index != ZYDIS_REGISTER_NONE)
                func(instr.operands[i].mem.index, ZYDIS_OPERAND_ACTION_READ, data);
        }
    }
}

typedef struct {bool success; commutative_ctx_t *ctx;} check_action_data_t;
static void check_actions_reg_iter(ZydisRegister reg, ZydisOperandActions actions, void *data) {
    check_action_data_t *dt = (check_action_data_t *)data;

    int unsized_reg = x86_get_unsized_register(reg);

    if (unsized_reg == REG_NONE || unsized_reg == REG_FLAGS)
        return;

    if (unsized_reg < 0 || unsized_reg == REG_RIP) {
        dt->success = false;
        return;
    }

    if (
        (actions & ZYDIS_OPERAND_ACTION_MASK_READ|ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
        dt->ctx->written_registers[unsized_reg])
        dt->success = false;
    if ((actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
        (dt->ctx->written_registers[unsized_reg] || dt->ctx->read_registers[unsized_reg]))
        dt->success = false;
}

static bool check_actions(ZydisDisassembledInstruction &instr, commutative_ctx_t *ctx) {
    check_action_data_t dt = {0};
    dt.success = true;
    dt.ctx = ctx;

    for (size_t i = 0; i < instr.info.operand_count; i++) {
        if (
            (instr.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY ||
            instr.operands[i].type == ZYDIS_OPERAND_TYPE_POINTER) &&
            (instr.operands[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
            return false;
    }

    iter_regs(instr, check_actions_reg_iter, &dt);
    return dt.success;
}

static void update_registers_iter(ZydisRegister reg, ZydisOperandActions actions, void *data) {
    commutative_ctx_t *ctx = (commutative_ctx_t *)data;

    int unsized_reg = x86_get_unsized_register(reg);

    if (unsized_reg <= REG_NONE)
        return;

    if (actions & ZYDIS_OPERAND_ACTION_MASK_READ)
        ctx->read_registers[unsized_reg] = 1;
    if (actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
        ctx->written_registers[unsized_reg] = 1;
}

static bool is_commutative(ZydisDisassembledInstruction &instr, commutative_ctx_t *ctx) {
    if (!check_actions(instr, ctx))
        return false;
    
    iter_regs(instr, update_registers_iter, ctx);
    return true;
}

static void clean_alone_commutatives(std::vector<poly_instr_t> &instrs) {
    for (size_t i = 0; i < instrs.size(); i++) {
        if (instrs[i].is_commutative) {
            if (
                (i == 0 || instrs[i-1].group_id != instrs[i].group_id) &&
                ((i == instrs.size()-1) || instrs[i+1].group_id != instrs[i].group_id)) {
                instrs[i].group_id = 0;
                instrs[i].is_commutative = 0;
            }
        }
    }
}

void x86_group_commutative_ops(std::vector<poly_instr_t> &instrs, int &group_id) {
    commutative_ctx_t ctx = {0};

    group_id++;
    for (size_t i = 0; i < instrs.size(); i++) {
        if (instrs[i].group_id) {
            group_id++;
            memset(&ctx, 0, sizeof(ctx));
            continue;
        }

        /*  if it is a jump destination,
            then it can't be inverted with previous instructions */
        if (instrs[i].is_jmp_dst) {
            memset(&ctx, 0, sizeof(ctx));
            group_id++;
        }

        if (is_commutative(instrs[i].instruction, &ctx)) {
            instrs[i].group_id = group_id;
            instrs[i].is_commutative = true;
        } else {
            group_id++;
            memset(&ctx, 0, sizeof(ctx));
            /*  if is it not commutative, check if it is contextual
                if it is, then add it to the next commutative group */
            if (is_commutative(instrs[i].instruction, &ctx)) {
                instrs[i].group_id = group_id;
                instrs[i].is_commutative = true;
            } else
                memset(&ctx, 0, sizeof(ctx));
        }
    }

    clean_alone_commutatives(instrs);
}