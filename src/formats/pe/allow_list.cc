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

#include "../../structs.hh"
#include "../../AllowList.hh"

void pe_gen_polylist(runtime_t &runtime, AllowList &polylist) {
    polylist.set_default(!runtime.only_explicit_polyform);

    if (!runtime.polyform_all) {
        polylist.add_string("__mingw_invalidParameterHandler", false);
        polylist.add_string("pre_c_init", false);
        polylist.add_string("pre_cpp_init", false);
        polylist.add_string("__tmainCRTStartup", false);
        polylist.add_string("WinMainCRTStartup", false);
        polylist.add_string("mainCRTStartup", false);
        polylist.add_string("atexit", false);
        polylist.add_string("__gcc_register_frame", false);
        polylist.add_string("__gcc_deregister_frame", false);
        polylist.add_string("__do_global_dtors", false);
        polylist.add_string("__do_global_ctors", false);
        polylist.add_string("__main", false);
        polylist.add_string("_setargv", false);
        polylist.add_string("__dyn_tls_dtor", false);
        polylist.add_string("__dyn_tls_init", false);
        polylist.add_string("__tlregdtor", false);
        polylist.add_string("_matherr", false);
        polylist.add_string("_fpreset", false);
        polylist.add_string("fpreset", false);
        polylist.add_string("__report_error", false);
        polylist.add_string("mark_section_writable", false);
        polylist.add_string("_pei386_runtime_relocator", false);
        polylist.add_string("__mingw_raise_matherr", false);
        polylist.add_string("__mingw_setusermatherr", false);
        polylist.add_string("_gnu_exception_handler", false);
        polylist.add_string("__mingwthr_run_key_dtors.part.0", false);
        polylist.add_string("___w64_mingwthr_add_key_dtor", false);
        polylist.add_string("___w64_mingwthr_remove_key_dtor", false);
        polylist.add_string("__mingw_TLScallback", false);
        polylist.add_string("_ValidateImageBase", false);
        polylist.add_string("_FindPESection", false);
        polylist.add_string("_FindPESectionByName", false);
        polylist.add_string("__mingw_GetSectionForAddress", false);
        polylist.add_string("__mingw_GetSectionCount", false);
        polylist.add_string("_FindPESectionExec", false);
        polylist.add_string("_GetPEImageBase", false);
        polylist.add_string("_IsNonwritableInCurrentImage", false);
        polylist.add_string("__mingw_enum_import_library_names", false);
        polylist.add_string("__p__fmode", false);
        polylist.add_string("__p__commode", false);
        polylist.add_string("__p__acmdln", false);
        polylist.add_string("mingw_get_invalid_parameter_handler", false);
        polylist.add_string("_get_invalid_parameter_handler", false);
        polylist.add_string("mingw_set_invalid_parameter_handler", false);
        polylist.add_string("_set_invalid_parameter_handler", false);
        polylist.add_string("__acrt_iob_func", false);
        polylist.add_string("register_frame_ctor", false);

        polylist.add_regex("__dyn_tls_dtor@.*", false);
        polylist.add_regex("__dyn_tls_init@.*", false);
        polylist.add_regex("_gnu_exception_handler@.*", false);
    }

    polylist.add_list(runtime.user_polylist);
}