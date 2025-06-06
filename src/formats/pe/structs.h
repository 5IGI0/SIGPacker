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

/**
 * This file includes structures and defines copied from the Windows API (WinAPI)
 * and/or Wine. These were not written by the author of this file but were included
 * to ensure access to necessary definitions and structures. Proper licensing and
 * permissions should be considered when using these components.
**/

#ifndef FMT_PE_STRUCTS_H
#define FMT_PE_STRUCTS_H

#include <stdint.h>

#include "defines.h"

typedef uint16_t      WORD;
typedef uint32_t      DWORD;
typedef uint8_t       BYTE;
typedef uint64_t      ULONGLONG;
typedef uint32_t      ULONG;
typedef int16_t       SHORT;
typedef uint16_t      USHORT;
typedef uintptr_t     ULONG_PTR;
typedef BYTE          BOOLEAN;
typedef void          *PVOID;
typedef wchar_t       WCHAR;
typedef unsigned char UCHAR;
typedef WCHAR         *PWSTR;
typedef PVOID         HANDLE;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _IMAGE_DOS_HEADER {
  WORD  e_magic;      /* 00: MZ Header signature */
  WORD  e_cblp;       /* 02: Bytes on last page of file */
  WORD  e_cp;         /* 04: Pages in file */
  WORD  e_crlc;       /* 06: Relocations */
  WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
  WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
  WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
  WORD  e_ss;         /* 0e: Initial (relative) SS value */
  WORD  e_sp;         /* 10: Initial SP value */
  WORD  e_csum;       /* 12: Checksum */
  WORD  e_ip;         /* 14: Initial IP value */
  WORD  e_cs;         /* 16: Initial (relative) CS value */
  WORD  e_lfarlc;     /* 18: File address of relocation table */
  WORD  e_ovno;       /* 1a: Overlay number */
  WORD  e_res[4];     /* 1c: Reserved words */
  WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
  WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
  WORD  e_res2[10];   /* 28: Reserved words */
  DWORD e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

/* NOTE: define from the WINE project. (LGPL) */
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD  Magic; /* 0x20b */
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _IMAGE_OPTIONAL_HEADER {

  /* Standard fields */

  WORD  Magic; /* 0x10b or 0x107 */	/* 0x00 */
  BYTE  MajorLinkerVersion;
  BYTE  MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;		/* 0x10 */
  DWORD BaseOfCode;
  DWORD BaseOfData;

  /* NT additional fields */

  DWORD ImageBase;
  DWORD SectionAlignment;		/* 0x20 */
  DWORD FileAlignment;
  WORD  MajorOperatingSystemVersion;
  WORD  MinorOperatingSystemVersion;
  WORD  MajorImageVersion;
  WORD  MinorImageVersion;
  WORD  MajorSubsystemVersion;		/* 0x30 */
  WORD  MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;			/* 0x40 */
  WORD  Subsystem;
  WORD  DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;		/* 0x50 */
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; /* 0x60 */
  /* 0xE0 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

/* NOTE: structure from the WINE project. (LGPL) */
typedef struct _IMAGE_NT_HEADERS {
  DWORD Signature; /* "PE"\0\0 */	/* 0x00 */
  IMAGE_FILE_HEADER FileHeader;		/* 0x04 */
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;	/* 0x18 */
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#define IMAGE_FIRST_SECTION(ntheader) \
  ((PIMAGE_SECTION_HEADER)(ULONG_PTR)((const BYTE *)&((const IMAGE_NT_HEADERS32 *)(ntheader))->OptionalHeader + \
                           ((const IMAGE_NT_HEADERS32 *)(ntheader))->FileHeader.SizeOfOptionalHeader))

/* NOTE: define from the WINE project. (LGPL) */
#define IMAGE_SIZEOF_SHORT_NAME 8

/* NOTE: structure from the WINE project. (+ removed VirtualSize/PhysicalAddress union) */
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  DWORD VirtualSize;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

/* NOTE: structure from the WINE project. (i added packed attribute) */
typedef struct _IMAGE_SYMBOL {
    union {
        BYTE    ShortName[8];
        struct {
            DWORD   Short;
            DWORD   Long;
        } Name;
        DWORD   LongName[2];
    } N;
    DWORD   Value;
    SHORT   SectionNumber;
    WORD    Type;
    BYTE    StorageClass;
    BYTE    NumberOfAuxSymbols;
} __attribute__((packed)) IMAGE_SYMBOL;
typedef IMAGE_SYMBOL *PIMAGE_SYMBOL;

/* NOTE: structure from the WINE project. (removed characteristics + packed) */
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	DWORD	OriginalFirstThunk;	/* RVA to original unbound IAT */
	DWORD	TimeDateStamp;	/* 0 if not bound,
				 * -1 if bound, and real date\time stamp
				 *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
				 * (new BIND)
				 * otherwise date/time stamp of DLL bound to
				 * (Old BIND)
				 */
	DWORD	ForwarderChain;	/* -1 if no forwarders */
	DWORD	Name;
	/* RVA to IAT (if bound this IAT has actual addresses) */
	DWORD	FirstThunk;
} __attribute__((packed)) IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

/* NOTE: define from the WINE project. (LGPL) */
typedef struct _IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;
		ULONGLONG Function;
		ULONGLONG Ordinal;
		ULONGLONG AddressOfData;
	} u1;
} IMAGE_THUNK_DATA64,*PIMAGE_THUNK_DATA64;

/* NOTE: define from the WINE project. (LGPL) */
typedef struct _IMAGE_THUNK_DATA32 {
	union {
		DWORD ForwarderString;
		DWORD Function;
		DWORD Ordinal;
		DWORD AddressOfData;
	} u1;
} IMAGE_THUNK_DATA32,*PIMAGE_THUNK_DATA32;

/* NOTE: define from the WINE project. (LGPL) */
typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD	Hint;
	BYTE	Name[1];
} IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

/* NOTE: define from the WINE project. (LGPL) */
typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD	Characteristics;
	DWORD	TimeDateStamp;
	WORD	MajorVersion;
	WORD	MinorVersion;
	DWORD	Name;
	DWORD	Base;
	DWORD	NumberOfFunctions;
	DWORD	NumberOfNames;
	DWORD	AddressOfFunctions;
	DWORD	AddressOfNames;
	DWORD	AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

/* NOTE: define from the WINE project. (LGPL) */
typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG   StartAddressOfRawData;
    ULONGLONG   EndAddressOfRawData;
    ULONGLONG   AddressOfIndex;
    ULONGLONG   AddressOfCallBacks;
    DWORD       SizeOfZeroFill;
    DWORD       Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

/* NOTE: define from the WINE project. (LGPL) */
typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;
    DWORD   AddressOfCallBacks;
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

#endif