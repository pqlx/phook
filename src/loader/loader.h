#pragma once

#include <stdlib.h>

int inferior_load_elf(inferior_t*);

int ptrace_sys_open(pid_t, char*, int);
int ptrace_sys_close(pid_t, int);
int ptrace_sys_mmap(pid_t, void*, size_t, int, int, int, off_t);

