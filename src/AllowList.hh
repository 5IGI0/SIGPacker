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

#ifndef FINDSET_HH
#define FINDSET_HH

#include <regex>
#include <string>
#include <vector>

typedef struct {
    std::regex reg;
    std::string str;
    bool is_regex;
    bool is_allowed;
} AllowList_entry_t;

class AllowList {
    public:
    AllowList();
    void set_default(bool default_val);
    void add_list(AllowList const &list);
    void add_string(char const *str,       bool is_allowed);
    void add_regex(std::string const &str, bool is_allowed);
    bool allowed(char const *str);
    private:
    bool default_val;
    std::vector<AllowList_entry_t> entries;
};

#endif