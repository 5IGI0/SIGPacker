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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

uint8_t *load_file(char *path, size_t *outlen) {
    FILE *fp = fopen(path, "rb");

    if (fp == NULL)
        return NULL;

    int ret = fseek(fp, 0, SEEK_END);
    long pos = ftell(fp);
    ret |= fseek(fp, 0, SEEK_SET);

    if (pos < 0 || ret < 0) {
        fclose(fp);
        return NULL;
    }

    uint8_t *content = malloc(pos);
    if (content)
        fread(content, 1, pos, fp);

    *outlen = pos;
    fclose(fp);
    return content;
}

uint8_t *memdup(uint8_t *buff, size_t len) {
    uint8_t *ret = malloc(len);
    memcpy(ret, buff, len);
    return ret;
}