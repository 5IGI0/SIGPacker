#!/bin/sh

# This file is part of SIGPacker. SIGPacker is free software:
# you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# SIGPacker is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# 
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with SIGPacker.
# If not, see <https://www.gnu.org/licenses/>. 
#
# Copyright 2024, 2025 5IGI0 / Ethan L. C. Lorenzetti

gcc -m32 -DTARGET_32=1 -nostdlib -static hide_linkers/x86.c -o hide_linkers/x86.o -masm=intel -Os -fno-builtin -Ttext=0x0 -fPIC
objcopy -j .text -O binary hide_linkers/x86.o hide_linkers/x86.raw
xxd -n pe_x86_linker -i hide_linkers/x86.raw ../src/formats/pe/linkers/x86.c
objdump -d hide_linkers/x86.o|grep '<do_linking>'|cut -d' ' -f1|sed 's/^/unsigned int pe_x86_linker_entry = 0x/g' >> ../src/formats/pe/linkers/x86.c
echo ';' >> ../src/formats/pe/linkers/x86.c