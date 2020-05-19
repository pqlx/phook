#pragma once

#include <stdlib.h>

/* These helper functions return the original 8-byte value at the addr,
 * as to not completely waste the PEEKDATA call in some scenarios */
uint64_t ptrace_write_u32(pid_t, void*, int32_t);
uint64_t ptrace_write_u16(pid_t, void*, uint16_t);
uint64_t ptrace_write_u8(pid_t,  void*, uint8_t);
