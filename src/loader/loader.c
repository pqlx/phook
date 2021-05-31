#include <string.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <stdio.h>

#include "util/trace.h"
#include "hook.h"



#include "loader/loader.h"

int inferior_load_elf(inferior_t* inferior)
{
    /* Load the to-be-injected ELF file into the inferior's address space */
    
    return 0;
}


/* Some syscall stubs */

int ptrace_sys_open(pid_t pid, char* path, int mode)
{

    #define NULL_16  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    #define NULL_64 NULL_16, NULL_16, NULL_16, NULL_16
    #define NULL_256 NULL_64, NULL_64, NULL_64, NULL_64
    

    uint64_t current_rip = ptrace_get_reg_u64(pid, RIP);

    uint8_t shellcode[] = {
        0xe9, 0x00, 0x01, 0x00, 0x00, /* jmp start_syscall */
        NULL_256,
        /* start_syscall: */
        0x31, 0xc0, /* xor eax, eax */
        0xb0, 0x02, /* mov al, SYS_open (0x02) */
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* movabs rdi, <i64> */
        0xbe, 0x00, 0x00, 0x00, 0x00, /* mov esi, <i32> */
        0x0f, 0x05 /* syscall */
    };

    strncpy((char*)&shellcode[5], path, 0x100);
    /* Patch in pointer to path */
    *((uint64_t*)&shellcode[5 + 0x100 + 6]) = current_rip + 0x05;
    /* Patch in mode */
    *((uint32_t*)&shellcode[5 + 0x100 + 6 + 9]) = (uint32_t)mode;
    
    return ptrace_execute_syscall(pid, (const uint8_t*)&shellcode, sizeof shellcode);

}


int ptrace_sys_close(pid_t pid, int fd)
{
    uint8_t shellcode[] = {
        0x31, 0xc0, /* xor eax, eax */
        0xb0, 0x03, /* mov al, SYS_close (0x03) */
        0xbf, 0x00, 0x00, 0x00, 0x00, /* mov edi, <i32> */
        0x0f, 0x05 /* syscall */
    };
    
    /* Patch in fd */
    *((uint32_t*)&shellcode[5]) = (uint32_t) fd;

    return ptrace_execute_syscall(pid, shellcode, sizeof shellcode);

}

int ptrace_sys_mmap(pid_t pid, void* addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    uint8_t shellcode[] = {
        0x31, 0xc0, /* xor eax, eax */
        0xb0, 0x09, /* mov al, SYS_mmap (0x09) */
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* movabs rdi, <i64> */
        0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* movabs rsi, <i64> */
        0xba, 0x00, 0x00, 0x00, 0x00, /* mov edx, <i32> */
        0x41, 0xba, 0x00, 0x00, 0x00, 0x00, /* mov r10d, <i32> */
        0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov r8d, <i32> */
        0x41, 0xb9, 0x00, 0x00, 0x00, 0x00, /* mov r9d, <i32> */
        0x0f, 0x05 /* syscall */
    };

    *((uint64_t*)&shellcode[6]) = (uint64_t)addr;
    *((uint64_t*)&shellcode[16]) = (uint64_t)length;
    *((uint32_t*)&shellcode[25]) = (uint32_t)prot;
    *((uint32_t*)&shellcode[31]) = (uint32_t)flags;
    *((uint32_t*)&shellcode[37]) = (uint32_t)fd;
    *((uint32_t*)&shellcode[43]) = (uint32_t)offset;

    return ptrace_execute_syscall(pid, shellcode, sizeof shellcode);
}
