#include <stdlib.h>
#include <stdio.h>
#include "pe_loader.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s <filename>\n", argv[0]);
    return 1;
  }
  printf("Trying to load PE file.\n");
  void *entry_pointer = LoadPe(argv[1]);
  if (entry_pointer != NULL) {
    ((void (*)()) entry_pointer)();
  } else {
    printf("Error while loading PE file\n");
    return 1;
  }
  return 0;
}
