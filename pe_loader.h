//
// Created by bnc on 05.10.2023.
//

#ifndef LANGUAGE_C__PE_LOADER_H
#define LANGUAGE_C__PE_LOADER_H
#include <windows.h>
#include <winbase.h>
#include <winnt.h>
#include <stdbool.h>
#include <stdio.h>
#define PE64 0x20B
#define PE32 0x10B
#define PE_MAGIC_NUMBER 23117
typedef struct _IMPORT_RESULT {

};
HANDLE LoadPe(char *filename);
long get_lfanew(HANDLE file_h);
WINBOOL write_file_header(HANDLE file_h, LPVOID section_base, DWORD size);
BOOL load_sections(HANDLE file_h,
                   PIMAGE_NT_HEADERS pimage_nt_h,
                   LPVOID image_base,
                   long lfanew,
                   LPVOID *section_base, PIMAGE_SECTION_HEADER sections);
HANDLE read_pe(char *filename);
PIMAGE_NT_HEADERS get_nt_headers(HANDLE *file_h, long lfanew);
BOOL make_relocations(PIMAGE_NT_HEADERS pimage_nt_h, LPVOID image_base);
DWORD get_section_protection(DWORD sc);
BOOL process_import(LPVOID image_base, PIMAGE_NT_HEADERS pimage_nt_h);
#endif //LANGUAGE_C__PE_LOADER_H
