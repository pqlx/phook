#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


#define ptrace_write_u64(pid, addr, value) ptrace(PTRACE_POKEDATA, (pid), (addr), (value))


uint64_t ptrace_read_write_u64(pid_t, void*, uint64_t); /* for consistency */
uint64_t ptrace_read_write_u32(pid_t, void*, uint32_t);
uint64_t ptrace_read_write_u16(pid_t, void*, uint16_t);
uint64_t ptrace_read_write_u8(pid_t,  void*, uint8_t);

uint8_t* ptrace_memcpy(pid_t, void*, const void*, size_t, bool);
