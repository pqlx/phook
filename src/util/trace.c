#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trace.h"
#include "richtext.h"

uint64_t ptrace_read_u64(pid_t pid, void* addr)
{
    return ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
}

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


#define print_reg_128(regs, reg, base, offset) printf(TERM_COLOR_RED "%-12s" TERM_COLOR_CYAN "0x%.16llx%.16llx\n" TERM_RESET, \
        "$" #reg ":", \
        ((long long unsigned int*)(&regs->base))[2*offset + 1], \
        ((long long unsigned int*)(&regs->base))[2*offset])
#define print_reg(regs, reg)                   printf(TERM_COLOR_RED "%-12s" TERM_COLOR_CYAN "0x%.16llx\n" TERM_RESET, "$" #reg ":", (regs)->reg)
#define print_reg_32(regs, reg)                printf(TERM_COLOR_RED "%-12s" TERM_COLOR_CYAN "0x%.8x\n"    TERM_RESET, "$" #reg ":", (regs)->reg)
#define print_reg_16(regs, reg)                printf(TERM_COLOR_RED "%-12s" TERM_COLOR_CYAN "0x%.4hx\n"   TERM_RESET, "$" #reg ":", (regs)->reg)

/* Monkey code but what do you do.. */
void print_aregs(struct user_aregs_struct* aregs)
{
    puts( TERM_COLOR_MAGENTA "General purpose registers:" TERM_RESET);
    print_regs (&aregs->regs);
    puts("\n" TERM_COLOR_MAGENTA "Floating point registers:" TERM_RESET);
    print_fpregs(&aregs->fpregs);
}

void print_regs(struct user_regs_struct* regs)
{
   print_reg(regs, rax);
   print_reg(regs, rbx);
   print_reg(regs, rcx);
   print_reg(regs, rdx);
   print_reg(regs, rsp);
   print_reg(regs, rbp);
   print_reg(regs, rsi);
   print_reg(regs, rdi);
   print_reg(regs, rip);
   print_reg(regs, r8);
   print_reg(regs, r9);
   print_reg(regs, r10);
   print_reg(regs, r11);
   print_reg(regs, r12);
   print_reg(regs, r13);
   print_reg(regs, r14);
   print_reg(regs, r15);
   /*
    * TODO maybe segment registers can be added later.
    * I do not deem it useful for now
    * */
}

void print_fpregs(struct user_fpregs_struct* fregs)
{
    print_reg_128(fregs, st0, st_space, 0);
    print_reg_128(fregs, st1, st_space, 1);
    print_reg_128(fregs, st2, st_space, 2);
    print_reg_128(fregs, st3, st_space, 3);
    print_reg_128(fregs, st4, st_space, 4);
    print_reg_128(fregs, st5, st_space, 5);
    print_reg_128(fregs, st6, st_space, 6);
    print_reg_128(fregs, st7, st_space, 7);

    print_reg_16(fregs, cwd);
    print_reg_16(fregs, swd);
    print_reg_16(fregs, ftw);
    print_reg_16(fregs, fop);
    print_reg(fregs, rip);
    print_reg(fregs, rdp);
    print_reg_32(fregs, mxcsr);
    print_reg_32(fregs, mxcr_mask);

    print_reg_128(fregs, xmm0, xmm_space, 0);
    print_reg_128(fregs, xmm1, xmm_space, 1);
    print_reg_128(fregs, xmm2, xmm_space, 2);
    print_reg_128(fregs, xmm3, xmm_space, 3);
    print_reg_128(fregs, xmm4, xmm_space, 4);
    print_reg_128(fregs, xmm5, xmm_space, 5);
    print_reg_128(fregs, xmm6, xmm_space, 6);
    print_reg_128(fregs, xmm7, xmm_space, 7);
    print_reg_128(fregs, xmm8, xmm_space, 8);
    print_reg_128(fregs, xmm9, xmm_space, 9);
    print_reg_128(fregs, xmm10, xmm_space, 10);
    print_reg_128(fregs, xmm11, xmm_space, 11);
    print_reg_128(fregs, xmm12, xmm_space, 12);
    print_reg_128(fregs, xmm13, xmm_space, 13);
    print_reg_128(fregs, xmm14, xmm_space, 14);
    print_reg_128(fregs, xmm15, xmm_space, 15);
    
}

/*
 * Inefficient but easy register state operations.
 * If we need performance, use POKEUSER and PEEKUSER
 * to only write/read to the affected registers 
 * */

struct user_aregs_struct* ptrace_get_aregs(pid_t pid)
{
    struct user_aregs_struct* result;

    result = calloc(1, sizeof *result);

    ptrace(PTRACE_GETREGS, pid, NULL, &result->regs);
    ptrace(PTRACE_GETFPREGS, pid, NULL, &result->fpregs);

    return result;
}

void ptrace_set_aregs(pid_t pid, struct user_aregs_struct* aregs)
{
    ptrace(PTRACE_SETREGS, pid, NULL, &aregs->regs);
    ptrace(PTRACE_SETFPREGS, pid, NULL, &aregs->fpregs); 
}

struct user_regs_struct* ptrace_get_regs(pid_t pid)
{
    struct user_regs_struct* result;

    result = calloc(1, sizeof *result);
    ptrace(PTRACE_GETREGS, pid, NULL, result);
    return result;
}

void ptrace_set_regs(pid_t pid, struct user_regs_struct* regs)
{
    ptrace(PTRACE_SETREGS, pid, NULL, regs);
}


struct user_fpregs_struct* ptrace_get_fpregs(pid_t pid)
{
    struct user_fpregs_struct* result;
    result = calloc(1, sizeof *result);
    ptrace(PTRACE_GETFPREGS, pid, NULL, result);
    return result;
}

void ptrace_set_fpregs(pid_t pid, struct user_fpregs_struct* fpregs)
{
    ptrace(PTRACE_SETFPREGS, pid, NULL, fpregs);
}

void ptrace_memcpy_from(pid_t pid, uint8_t* dest, void* src, size_t n)
{
    while(n != 0)
    {
        if(n >= 8)
            n -= sizeof (*(uint64_t*)dest++ = (uint64_t)ptrace_read_u64(pid, (uint64_t*)src++));
        
        else if(n >= 4)
            n -= sizeof (*(uint32_t*)dest++ = (uint32_t)ptrace_read_u64(pid, (uint32_t*)src++)); 

        else if(n >= 2)
            n -= sizeof (*(uint16_t*)dest++ = (uint16_t)ptrace_read_u64(pid, (uint16_t*)src++));
        else
            n -= sizeof (*(uint8_t*) dest++ = (uint8_t)ptrace_read_u64(pid, (uint16_t*)src++));
            
    }
} 

void ptrace_memcpy_to(pid_t pid, void* dest, const uint8_t* src, size_t n, uint8_t* old)
{
    /* Memcpy a `n`-sized buffer from `src` to tracee's `dest`.
     * if `old` is set, The old values are written to it.
     * A buffer of at least `n` bytes should be passed.
     * */
    
    uint64_t value;

    while(n != 0)
    {
        if(n >= 8)
        {
           if(old)
                *(uint64_t*)old++ = ptrace_read_write_u64(pid, dest, *(uint64_t*)src++);
           else
                ptrace_write_u64(pid, dest, *(uint64_t*)src++);

           n -= 8;
        }

        else if (n >= 4)
        {
            value = ptrace_read_write_u32(pid, dest, *(uint32_t*)src++);

            if(old)
                *(uint32_t*)old++ = (uint32_t)value;

            n -= 4;
        }
        else if (n >= 2)
        {
            value = ptrace_read_write_u16(pid, dest, *(uint16_t*)src++);

            if(old)
                *(uint16_t*)old++ = (uint16_t)value;
            
            n -= 2;
        }
        else
        {
            /* n == 1 */
            value = ptrace_read_write_u8(pid, dest, *(uint8_t*)src++);

            if(old)
                *old++ = (uint8_t)value;
            
            n--;
        }
    }
}



void ptrace_execute_shellcode(pid_t pid, const uint8_t* shellcode, size_t n, void* return_address)
{
    char epilogue[] = { 0xcc };

    size_t final_n = n + sizeof epilogue;
    uint8_t* final_shellcode = malloc(final_n);

    memcpy(final_shellcode, shellcode, n);
    memcpy(&final_shellcode[n], epilogue, sizeof epilogue);
     

}
