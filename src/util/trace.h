#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/user.h> /* user_regs_struct */

/*
 * https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86/sys/user.h.html
 */

#define ptrace_write_u64(pid, addr, value) ptrace(PTRACE_POKEDATA, (pid), (addr), (value))

/*
 * All registers.
 * We need this to correctly restore state.
 * The systemV ABI specifies some of the floating point registers to be cluttered.
 * */
struct user_aregs_struct {
    struct user_regs_struct   regs;
    struct user_fpregs_struct fpregs;   
};

uint64_t ptrace_read_u64(pid_t, void*);

uint64_t ptrace_read_write_u64(pid_t, void*, uint64_t); /* for consistency */
uint64_t ptrace_read_write_u32(pid_t, void*, uint32_t);
uint64_t ptrace_read_write_u16(pid_t, void*, uint16_t);
uint64_t ptrace_read_write_u8(pid_t,  void*, uint8_t);

void print_aregs (struct user_aregs_struct*);
void print_regs  (struct user_regs_struct*);
void print_fpregs(struct user_fpregs_struct*);

struct user_aregs_struct* ptrace_get_aregs(pid_t);
void ptrace_set_aregs(pid_t, struct user_aregs_struct*);

struct user_regs_struct* ptrace_get_regs(pid_t);
void ptrace_set_regs(pid_t, struct user_regs_struct*);

struct user_fpregs_struct* ptrace_get_fpregs(pid_t);
void ptrace_set_fpregs(pid_t, struct user_fpregs_struct*);

void ptrace_memcpy_from(pid_t, uint8_t*, void*, size_t);
void ptrace_memcpy_to(pid_t, void*, const uint8_t*, size_t, uint8_t*);
void ptrace_run_shellcode(pid_t, const uint8_t*, size_t, void*);
