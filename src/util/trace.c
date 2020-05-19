#include <sys/ptrace.h>

#include "trace.h"

uint64_t ptrace_write_u32(pid_t pid, void* addr, uint32_t value)
{
    uint64_t data, new; 
    
    data = new = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    new  &= 0xffffffff00000000;
    new  |= value;
    ptrace(PTRACE_POKEDATA, pid, addr, new);

    return data;
}

uint64_t ptrace_write_u16(pid_t pid, void* addr, uint16_t value)
{
    uint64_t data, new;
    
    data = new = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    new &= 0xffffffffffff0000;
    new |= value;
    ptrace(PTRACE_POKEDATA, pid, addr, new);

    return data;
}

uint64_t ptrace_write_u8(pid_t pid, void* addr, uint8_t value)
{
    uint64_t data, new;

    data = new = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    new &= 0xffffffffffffff00;
    new |= value;
    ptrace(PTRACE_POKEDATA, pid, addr, new);

    return data;
}
