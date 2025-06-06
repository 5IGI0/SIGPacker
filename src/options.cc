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

#include <getopt.h>

#include "structs.hh"

typedef enum {
    OPT_ID_NONE,
    OPT_ID_HIDE_IMPORT,
    OPT_ID_ONLY_EXPLICIT_POLYFORM,
    OPT_ID_POLYFORM_ALL,
    OPT_ID_POLYFORM,
    OPT_ID_POLYFORM_RE,
    OPT_ID_DONT_POLYFORM,
    OPT_ID_DONT_POLYFORM_RE,
} opt_id_t;

const struct option longopt_list[] = {
    (struct option){.name = "hide-import", .has_arg = 1, .val = OPT_ID_HIDE_IMPORT},
    // polyform-related
    (struct option){.name = "only-explicit-polyform",            .val = OPT_ID_ONLY_EXPLICIT_POLYFORM},
    (struct option){.name = "polyform-all",                      .val = OPT_ID_POLYFORM_ALL},
    (struct option){.name = "polyform",            .has_arg = 1, .val = OPT_ID_POLYFORM},
    (struct option){.name = "polyform-regex",      .has_arg = 1, .val = OPT_ID_POLYFORM_RE},
    (struct option){.name = "dont-polyform",       .has_arg = 1, .val = OPT_ID_DONT_POLYFORM},
    (struct option){.name = "dont-polyform-regex", .has_arg = 1, .val = OPT_ID_DONT_POLYFORM_RE},
    (struct option){0}};

int parse_opts(int argc, char **argv, runtime_t *runtime) {
    int long_index = 0;
    while (1) {
        int opt = getopt_long(argc, argv, "", longopt_list, NULL);
        if (opt == -1)
            break;

        switch (opt) {
            case OPT_ID_HIDE_IMPORT:
                runtime->hide_imports.push_back(optarg);
                break;
            case OPT_ID_ONLY_EXPLICIT_POLYFORM:
                runtime->only_explicit_polyform = true;
                break;
            case OPT_ID_POLYFORM_ALL:
                runtime->polyform_all = true;
                break;
            case OPT_ID_POLYFORM:
                runtime->user_polylist.add_string(optarg, true);
                break;
            case OPT_ID_POLYFORM_RE:
                runtime->user_polylist.add_regex(optarg, true);
                break;
            case OPT_ID_DONT_POLYFORM:
                runtime->user_polylist.add_string(optarg, false);
                break;
            case OPT_ID_DONT_POLYFORM_RE:
                runtime->user_polylist.add_regex(optarg, false);
                break;
        }
    }

    if (optind > argc-2) {
        printf("Usage: %s <input> <output>\n", argv[0]);
        return -1;
    }

    runtime->output_path    = argv[optind+1];
    runtime->input_path     = argv[optind];

    return 0;
}