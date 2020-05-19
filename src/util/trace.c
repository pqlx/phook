#include <sys/ptrace.h>

#include "trace.h"



uint64_t ptrace_read_write_u64(pid_t pid, void* addr, uint64_t value)
{
    /* This particular function should only be used if the output is desired.
     * otherwise just use the direct ptrace(PTRACE_POKETEXT) call.
     * */

    uint64_t data, new;

    data = new = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    new = value;
    ptrace(PTRACE_POKEDATA, pid, addr, new);

    return data;
}

uint64_t ptrace_read_write_u32(pid_t pid, void* addr, uint32_t value)
{
    uint64_t data, new; 
    
    data = new = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    new  &= 0xffffffff00000000;
    new  |= value;
    ptrace(PTRACE_POKEDATA, pid, addr, new);

    return data;
}

uint64_t ptrace_read_write_u16(pid_t pid, void* addr, uint16_t value)
{
    uint64_t data, new;
    
    data = new = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    new &= 0xffffffffffff0000;
    new |= value;
    ptrace(PTRACE_POKEDATA, pid, addr, new);

    return data;
}

uint64_t ptrace_read_write_u8(pid_t pid, void* addr, uint8_t value)
{
    uint64_t data, new;

    data = new = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    new &= 0xffffffffffffff00;
    new |= value;
    ptrace(PTRACE_POKEDATA, pid, addr, new);

    return data;
}

uint8_t* ptrace_memcpy(pid_t pid, void* dest, const void* src, size_t n, bool retain_old)
{
    /* Memcpy a `n`-sized buffer from `src` to tracee's `dest`.
     * if retain_old is set, a malloc'd pointer to the old data is returned.
     * */
    
    uint8_t *result = NULL, *cpy;

    if(retain_old)
    {
        result = cpy = malloc(n);
    }

    uint64_t value;

    while(n != 0)
    {
        if(n >= 8)
        {
           if(retain_old)
                *(uint64_t*)cpy++ = ptrace_read_write_u64(pid, dest, *(uint64_t*)src++);
           else
                ptrace_write_u64(pid, dest, *(uint64_t*)src++);

           n -= 8;
        }

        else if (n >= 4)
        {
            value = ptrace_read_write_u32(pid, dest, *(uint32_t*)src++);

            if(retain_old)
                *(uint32_t*)cpy++ = (uint32_t)value;

            n -= 4;
        }
        else if (n >= 2)
        {
            value = ptrace_read_write_u16(pid, dest, *(uint16_t*)src++);

            if(retain_old)
                *(uint16_t*)cpy++ = (uint16_t)value;
            
            n -= 2;
        }
        else
        {
            /* n == 1 */
            value = ptrace_read_write_u8(pid, dest, *(uint8_t*)src++);

            if(retain_old)
                *cpy++ = (uint8_t)value;
            
            n--;
        }
    }

    return result;
}
