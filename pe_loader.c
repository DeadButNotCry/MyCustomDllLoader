//
// Created by bnc on 05.10.2023.
//

#include "pe_loader.h"

void *LoadPe(char *filename) {
  HANDLE *pe_file_data;
  PIMAGE_NT_HEADERS pimage_nt_h;
  long lfanew;
  BOOL temp_res;
  pe_file_data = read_pe(filename);

  if (pe_file_data == INVALID_HANDLE_VALUE) {
    return NULL;
  }
  lfanew = get_lfanew(pe_file_data);
  if (lfanew == -1) {
    return NULL;
  }
  pimage_nt_h = get_nt_headers(pe_file_data, lfanew);
  if (pimage_nt_h == NULL) {
    return NULL;
  }
  LPVOID
      image_base = VirtualAlloc(NULL, pimage_nt_h->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
  if (image_base == NULL) {
    printf("Cannot allocate memory for image base\n");
    return NULL;
  }
  LPVOID section_base =
      VirtualAlloc(image_base, pimage_nt_h->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
  if (section_base == NULL) {
    printf("Cannot allocate memory for headers\n");
  }
  temp_res = write_file_header(pe_file_data, section_base, pimage_nt_h->OptionalHeader.SizeOfHeaders);
  if (!temp_res)
    return NULL;

  DWORD old_protection;
  temp_res = VirtualProtect(section_base, pimage_nt_h->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_protection);
  if (!temp_res) {
    DWORD last_err = GetLastError();
    printf("Cannot protect header part of image. With error: %lu\n", last_err);
    return NULL;
  }
  PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER) VirtualAlloc(NULL,
                                                                        sizeof(IMAGE_SECTION_HEADER)
                                                                            * pimage_nt_h->FileHeader.NumberOfSections,
                                                                        MEM_COMMIT | MEM_RESERVE,
                                                                        PAGE_READWRITE);
  temp_res = load_sections(pe_file_data, pimage_nt_h, image_base, lfanew, &section_base, sections);
  if (!temp_res) {
    printf("Cannot load sections.\n");
    return NULL;
  }
  temp_res = make_relocations(pimage_nt_h, image_base);
  if (!temp_res) {
    printf("Cannot make relocations\n");
    return NULL;
  }

  temp_res = process_import(image_base, pimage_nt_h);
  if (!temp_res) {
    printf("Cannot import libs.\n");
    return NULL;
  }

  for (WORD i = 0; i < pimage_nt_h->FileHeader.NumberOfSections; i++) {
    DWORD old_protect;
    temp_res = VirtualProtect(image_base + sections[i].VirtualAddress,
                              sections[i].Misc.VirtualSize,
                              get_section_protection(sections[i].Characteristics), &old_protection);
    if (!temp_res) {
      printf("Cannot protect section %s\n", sections[i].Name);
      return NULL;
    }

  }

  return NULL;
}

long get_lfanew(HANDLE file_h) {
  if (file_h == NULL) {
    return -1;
  }

  IMAGE_DOS_HEADER dos_header;
  DWORD n_read;
  BOOL readfile_res;
  readfile_res = ReadFile(file_h, &dos_header, sizeof(IMAGE_DOS_HEADER), &n_read, NULL);
  if (!readfile_res) {
    printf("Error while reading the file\n");
    return -1;
  }
  if (n_read != sizeof(IMAGE_DOS_HEADER)) {
    printf("Size of read bytes lower than IMAGE_DOS_HEADER: %lu < %llu", n_read, sizeof(IMAGE_DOS_HEADER));
    return -1;
  }
  if (dos_header.e_magic != PE_MAGIC_NUMBER) {
    printf("It's not a PE file.\n");
    return -1;
  }
  return dos_header.e_lfanew;
}

HANDLE read_pe(char *filename) {
  if (filename == NULL) {
    return INVALID_HANDLE_VALUE;
  }
  HANDLE file_h = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD error = GetLastError();
  if (error == 0 && file_h != INVALID_HANDLE_VALUE) {
    return file_h;
  } else if (error == 2) {
    printf("File not found\n");
    return INVALID_HANDLE_VALUE;
  }
}

PIMAGE_NT_HEADERS get_nt_headers(HANDLE file_h, long lfanew) {

  PIMAGE_NT_HEADERS
      res = (PIMAGE_NT_HEADERS) VirtualAlloc(NULL, sizeof(IMAGE_NT_HEADERS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  BOOL readheader_res;
  DWORD n_read;
  DWORD newPtr = SetFilePointer(file_h, lfanew, NULL, FILE_BEGIN);

  if (res == NULL) {
    printf("Cannot allocate memory for IMAGE_NT_HEADER\n");
    return NULL;
  }
  if (newPtr == INVALID_SET_FILE_POINTER) {
    DWORD error = GetLastError();
    printf("Error while setting file pointer. Error code: %lul\n", error);
    return NULL;
  }
  readheader_res = ReadFile(file_h, res, sizeof(IMAGE_NT_HEADERS), &n_read, NULL);
  if (n_read == sizeof(IMAGE_NT_HEADERS) && readheader_res) {
    newPtr = SetFilePointer(file_h, 0, NULL, FILE_BEGIN);
    if (newPtr == INVALID_SET_FILE_POINTER)
      return NULL;
    else
      return res;
  } else {
    printf("Cannot read NT_HEADER\n");
    return NULL;
  }
}

BOOL write_file_header(HANDLE file_h, LPVOID section_base, DWORD size) {
  DWORD number_of_bytes;
  BOOL res;
  res = ReadFile(file_h, section_base, size, &number_of_bytes, NULL);
  if (res && number_of_bytes == size) {
    return TRUE;
  } else {
    printf("Cannot write headers to section_base\n");
    return FALSE;
  }
}

BOOL load_sections(HANDLE file_h,
                   PIMAGE_NT_HEADERS pimage_nt_h,
                   LPVOID image_base,
                   long lfanew,
                   LPVOID *section_base, PIMAGE_SECTION_HEADER sections) {
  BOOL temp_res;
  DWORD temp_file_ptr, n;
  LONG offset_to_first_section = sizeof(IMAGE_NT_HEADERS) + lfanew;
  for (WORD i = 0; i < pimage_nt_h->FileHeader.NumberOfSections; ++i) {
    temp_file_ptr =
        SetFilePointer(file_h, offset_to_first_section + sizeof(IMAGE_SECTION_HEADER) * i, NULL, FILE_BEGIN);
    if (temp_file_ptr == INVALID_SET_FILE_POINTER) {
      printf("Cannot set file pointer\n");
      return FALSE;
    }
    temp_res = ReadFile(file_h, &sections[i], sizeof(IMAGE_SECTION_HEADER), &n, NULL);
    if (!temp_res || n != sizeof(IMAGE_SECTION_HEADER)) {
      printf("Cannot read SECTION_HEADER with index %hd\n", i);
      return FALSE;
    }
    DWORD virtual_section_size = sections[i].Misc.VirtualSize;
    DWORD raw_section_size = sections[i].SizeOfRawData;
    raw_section_size = min(raw_section_size, virtual_section_size);
    *section_base =
        VirtualAlloc(image_base + sections[i].VirtualAddress, virtual_section_size, MEM_COMMIT, PAGE_READWRITE);
    if (section_base == NULL) {
      printf("Cannot allocate memory for section.\t%d\n", i);
      return FALSE;
    }
    temp_file_ptr = SetFilePointer(file_h, sections[i].PointerToRawData, NULL, FILE_BEGIN);
    if (temp_file_ptr == INVALID_SET_FILE_POINTER) {
      printf("Cannot set pointer to start of section raw Data.\n");
      return FALSE;
    }
    n = 0;
    temp_res = ReadFile(file_h, *section_base, raw_section_size, &n, NULL);
    if (!temp_res || n != raw_section_size) {
      printf("Cannot read raw section Data\n");
      return FALSE;
    }
    printf("Successfully load the section \"%s\"\n", sections[i].Name);
  }
  return TRUE;

}

BOOL make_relocations(PIMAGE_NT_HEADERS pimage_nt_h, LPVOID image_base) {
  DWORD image_base_delta = (DWORD) (image_base) - pimage_nt_h->OptionalHeader.ImageBase;
  IMAGE_DATA_DIRECTORY reloc_dir = pimage_nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  PIMAGE_BASE_RELOCATION pbase_relocs = (PIMAGE_BASE_RELOCATION) (image_base + reloc_dir.VirtualAddress);
  PIMAGE_BASE_RELOCATION current_reloc = pbase_relocs;
  DWORD reloc_size = reloc_dir.Size;

  while ((DWORD) current_reloc - (DWORD) (pbase_relocs) < reloc_size) {
    DWORD mod_count = (current_reloc->SizeOfBlock - sizeof(current_reloc)) / 2;
    WORD *P = (WORD *) ((char *) current_reloc + sizeof(current_reloc));
    for (DWORD i = 0; i < mod_count; i++) {
      if (((*P) & 0xf000) != 0) {
        *((PDWORD) (image_base + current_reloc->VirtualAddress + ((*P) & 0x0fff))) +=
            image_base_delta;
      }
      P++;
    }
    current_reloc = (PIMAGE_BASE_RELOCATION) P;
  }
  return TRUE;
}

DWORD get_section_protection(DWORD sc) {
  DWORD result;
  result = 0;
  if ((sc & IMAGE_SCN_MEM_NOT_CACHED) != 0) {
    result |= PAGE_NOCACHE;
  }
  if ((sc & IMAGE_SCN_MEM_EXECUTE) != 0) {
    if ((sc & IMAGE_SCN_MEM_READ) != 0) {
      if ((sc & IMAGE_SCN_MEM_WRITE) != 0) {
        result |= PAGE_EXECUTE_READWRITE;
      } else {
        result |= PAGE_EXECUTE_READ;
      }
    } else {
      if ((sc & IMAGE_SCN_MEM_WRITE) != 0) {
        result |= PAGE_EXECUTE_WRITECOPY;
      } else {
        result |= PAGE_EXECUTE;
      }
    }
  } else {
    if ((sc & IMAGE_SCN_MEM_READ) != 0) {
      if ((sc & IMAGE_SCN_MEM_WRITE) != 0) {
        result |= PAGE_READWRITE;
      } else {
        result |= PAGE_READONLY;
      }
    } else {
      if ((sc & IMAGE_SCN_MEM_WRITE) != 0) {
        result |= PAGE_WRITECOPY;
      } else {
        result |= PAGE_NOACCESS;
      }
    }
  }
  return result;
}

BOOL process_import(LPVOID image_base, PIMAGE_NT_HEADERS pimage_nt_h) {
  IMAGE_DATA_DIRECTORY data_dir = pimage_nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (data_dir.VirtualAddress == 0) {
    return TRUE;
  }
  PIMAGE_IMPORT_DESCRIPTOR pimport_desc = image_base + data_dir.VirtualAddress;
  printf("Cannot load lib.\n");

  while (pimport_desc->Name != 0) {
    PCHAR plib_name = image_base + pimport_desc->Name;
    HMODULE hm = LoadLibraryA(plib_name);
    if (hm == NULL) {
      printf("Cannot load lib. Error %lu\n", GetLastError());
      return FALSE;
    }
    printf("Loaded: %s  \n", plib_name);

    PIMAGE_THUNK_DATA orig_first_thunk = (image_base + pimport_desc->OriginalFirstThunk);
    PIMAGE_THUNK_DATA first_thunk = (image_base + pimport_desc->FirstThunk);

    for (DWORD i = 0; orig_first_thunk[i].u1.AddressOfData != 0; i++) {
      PIMAGE_IMPORT_BY_NAME by_name;
      LPCSTR search_value;

      if (orig_first_thunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        search_value = (PCHAR) IMAGE_ORDINAL(orig_first_thunk[i].u1.Ordinal);
      } else {
        by_name = image_base + first_thunk[i].u1.AddressOfData;
        search_value = (LPCSTR) by_name->Name;
      }

      printf("\tFunction name: %s\n", search_value);
      DWORD ptr = (LONGLONG) GetProcAddress(hm, search_value);

      first_thunk->u1.Function = ptr;
      if (first_thunk->u1.Function == 0) {
        FreeLibrary(hm);
        return FALSE;
      }
    }
    pimport_desc++;
  }
  return TRUE;
}

BOOL process_export(LPVOID image_base, PIMAGE_NT_HEADERS pimage_nt_h) {
  if (image_base == NULL || pimage_nt_h == NULL) {
    return FALSE;
  }
  IMAGE_DATA_DIRECTORY data_dir = pimage_nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  PIMAGE_EXPORT_DIRECTORY pexport_dir = (PIMAGE_EXPORT_DIRECTORY) (image_base + data_dir.VirtualAddress);
  if (data_dir.Size == 0 || data_dir.VirtualAddress == 0) {
    return TRUE;
  }
}