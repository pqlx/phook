#pragma once

#include <stdint.h>
#include <stddef.h>

char* read_text_file(char*);
char* read_text_file_procfs(char*);
uint8_t* read_binary_file(char*, size_t*);
