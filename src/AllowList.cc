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

#include "AllowList.hh"
#include <cstring>
#include <regex>

AllowList::AllowList() {}

void AllowList::set_default(bool default_val) {
    this->default_val = default_val;
}

void AllowList::add_list(AllowList const &list) {
    this->entries.insert(this->entries.end(), list.entries.begin(), list.entries.end());
}

void AllowList::add_regex(std::string const &str, bool is_allowed) {
    AllowList_entry_t e = {
        .reg        = std::regex(str),
        .is_regex   = true,
        .is_allowed = is_allowed};
    this->entries.push_back(e);
}

void AllowList::add_string(char const *str, bool is_allowed) {
    AllowList_entry_t e = {
        .str        = str,
        .is_regex   = false,
        .is_allowed = is_allowed};
    this->entries.push_back(e);
}

bool AllowList::allowed(char const *str) {
    for (auto entry = this->entries.rbegin(); entry != this->entries.rend(); ++entry) {
        if (entry->is_regex) {
            if (std::regex_match(str, entry->reg))
                return entry->is_allowed;
        } else {
            if (std::strcmp(str, entry->str.c_str()) == 0)
                return entry->is_allowed;
        }
    }

    return this->default_val;
}