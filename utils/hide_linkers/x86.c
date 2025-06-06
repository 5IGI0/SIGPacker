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
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#include <immintrin.h>

#include "../../src/formats/pe/structs.h"
#include "../../src/formats/pe/linkers/linkers.h"

#define RESTRICTED_POINTER
#define LDR_DDAG_NODE void
typedef ULONGLONG LARGE_INTEGER;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _UNICODE_STRING {
    USHORT Length;        /* bytes */
    USHORT MaximumLength; /* bytes */
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, * RESTRICTED_POINTER PRLIST_ENTRY;


/* NOTE: structure from the WINE project. (LGPL) */
typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE *Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    } DUMMYUNIONNAME2;
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY          InLoadOrderLinks;
    LIST_ENTRY          InMemoryOrderLinks;
    LIST_ENTRY          InInitializationOrderLinks;
    void*               DllBase;
    void*               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING      FullDllName;
    UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    LIST_ENTRY          HashLinks;
    ULONG               TimeDateStamp;
    HANDLE              ActivationContext;
    void*               Lock;
    LDR_DDAG_NODE*      DdagNode;
    LIST_ENTRY          NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT *LoadContext;
    void*               ParentDllBase;
    void*               SwitchBackContext;
    RTL_BALANCED_NODE   BaseAddressIndexNode;
    RTL_BALANCED_NODE   MappingInfoIndexNode;
    ULONG_PTR           OriginalBase;
    LARGE_INTEGER       LoadTime;
    ULONG               BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG               ImplicitPathOptions;
    ULONG               ReferenceCount;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _PEB_LDR_DATA
{
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
#ifdef TARGET_32
    char            dummy1[0xC];
#else
    char            dummy1[0x18];
#endif
    PPEB_LDR_DATA   Ldr;
} PEB, *PPEB;

static inline __attribute__((always_inline)) uint64_t readgsqword(size_t offset) {
    uint64_t ret;
    __asm__(
        "mov %0, GS:[%1]" :
        "=r" (ret) :
        "r" (offset));
    return ret;
}

static inline __attribute__((always_inline)) uint64_t readfsdword(size_t offset) {
    uint32_t ret;
    __asm__(
        "mov %0, FS:[%1]" :
        "=r" (ret) :
        "r" (offset));
    return ret;
}

#ifdef TARGET_32
typedef hidden_import_32_t hidden_import_t;
#define PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS32
#define LINK_THUNK_TYPE uint32_t
#define CALL_CONV 
#else
typedef hidden_import_64_t hidden_import_t;
#define PIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64
#define LINK_THUNK_TYPE uint64_t
// NOTE: we force the microsoft call convention so it doesn't look weird in a PE file.
// (since we compile it with gcc, it uses the sysv convention by default)
#define CALL_CONV __attribute__((ms_abi)) 
#endif

// int (*my_hidden_strlen)(char const *) = NULL;

// hidden_import_t g_imports[] = {
//     {0x656e4c0, 0x07ab92be, (void **)&my_hidden_strlen}};

uint32_t CALL_CONV hash_func(const unsigned char *s, size_t len, int _);

int CALL_CONV my_strlen(char *str) {
    size_t i = 0;
    while (str[i]) i++;
    return i;
}

void CALL_CONV do_linking(hidden_import_t *imports, size_t import_count) {
#if TARGET_32
    PPEB peb = (PPEB)readfsdword(0x30);
#else
    PPEB peb = (PPEB)readgsqword(0x60);
#endif

    PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
    PLIST_ENTRY table = &ldr->InMemoryOrderModuleList;

    while (table)
    {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)table->Flink;
        table = table->Flink;

        if (table == &ldr->InMemoryOrderModuleList)
            break; // wine has an infinite linked-list, so we need to check if we are not looping on the original one.
        if (entry->FullDllName.Buffer == NULL)
            break;

        // convert dll name to lowercase
        uint16_t lower_dllname[entry->FullDllName.Length/2];
        for (size_t i = 0; i < entry->FullDllName.Length/2;  i++) {
            uint16_t cchar = ((uint16_t *)entry->FullDllName.Buffer)[i];
            if (cchar >= 'A' && cchar <= 'Z')
                lower_dllname[i] = cchar + ('a' - 'A');
            else
                lower_dllname[i] = cchar;
        }

        uint32_t dll_hash = hash_func((char *)lower_dllname, entry->FullDllName.Length, 0);
        uint8_t  *dll_base = (uint8_t *)entry->InInitializationOrderLinks.Flink;
        int success = 0;
        for (size_t i = 0; i < import_count; i++)
            success |= imports[i].dll_name == dll_hash;

        if (!success) continue;

        PIMAGE_NT_HEADERS hdr = (PIMAGE_NT_HEADERS)(dll_base + ((PIMAGE_DOS_HEADER)dll_base)->e_lfanew);
        if (!hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
            continue;

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(dll_base + hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        uint32_t *names = (uint32_t *)(dll_base + exp->AddressOfNames);
        uint32_t *funcs_offset = (uint32_t *)(dll_base + exp->AddressOfFunctions);

        for (size_t i = 0; i < exp->NumberOfNames; i++) {
            uint32_t func_name = hash_func(dll_base + names[i], my_strlen(dll_base + names[i]), 0);
            for (size_t j = 0; j < import_count; j++) {
                if (imports[j].dll_name == dll_hash && imports[j].func_name == func_name) {
                    *(LINK_THUNK_TYPE *)imports[j].IAT_addr = (LINK_THUNK_TYPE)(dll_base + funcs_offset[i]);
                }
            }
        }
    }
}

uint32_t CALL_CONV hash_func(const unsigned char *s, size_t len, int _) {
    uint32_t h = 0, high;
    while (len)
    {
        h = (h << 4) + *s++;
        if ((high = h & 0xF0000000))
            h ^= high >> 24;
        h &= ~high;
        len--;
    }
    return h;
}

char _start[0];

// int main(void) {
//     do_linking(g_imports, sizeof(g_imports)/sizeof(g_imports[0]));

//     printf("call to my hidden import: %d\n", my_hidden_strlen("cacag"));
// }