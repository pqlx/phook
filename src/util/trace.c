#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "trace.h"
#include "richtext.h"
#include "util.h"

/*
 * TODO maybe abstrace the read_write_uxx and get_set_uxx
 * functionality, since they are the same thing with a diff. flag.
 * Either way it's not really a big deal. 
 * */


uint64_t ptrace_read_write_u64(pid_t pid, void* addr, uint64_t value)
{
    /* This particular function should only be used if the output is desired.
     * otherwise just use the direct ptrace(PTRACE_POKETEXT) call.
     * */

    uint64_t data, new;

    data = new = ptrace_read_u64(pid, addr);
    new = value;
    ptrace_write_u64(pid, addr, new);

    return data;
}

uint64_t ptrace_read_write_u32(pid_t pid, void* addr, uint32_t value)
{
    uint64_t data, new; 
    
    data = new = ptrace_read_u64(pid, addr);
    new  &= 0xffffffff00000000;
    new  |= value;
    ptrace_write_u64(pid, addr, new);

    return data;
}

uint64_t ptrace_read_write_u16(pid_t pid, void* addr, uint16_t value)
{
    uint64_t data, new;
    
    data = new = ptrace_read_u64(pid, addr);
    new &= 0xffffffffffff0000;
    new |= value;
    ptrace_write_u64(pid, addr, new);

    return data;
}

uint64_t ptrace_read_write_u8(pid_t pid, void* addr, uint8_t value)
{
    uint64_t data, new;

    data = new = ptrace_read_u64(pid, addr);
    new &= 0xffffffffffffff00;
    new |= value;
    ptrace_write_u64(pid, addr, new);

    return data;
}

/*
 * The following routines take an offset denoting the register,
 * these are found in <sys/reg.h>.
 * */ 

uint64_t ptrace_get_set_reg_u64(pid_t pid, uint64_t offset, uint64_t value)
{
    uint64_t data;
    
    data = ptrace_get_reg_u64(pid, offset);
    ptrace_set_reg_u64(pid, offset, value);

    return data;
}

uint64_t ptrace_get_set_reg_u32(pid_t pid, uint64_t offset, uint32_t value)
{
    uint64_t data, new;
    
    data = new = ptrace_get_reg_u64(pid, offset);
    new &= 0xffffffff00000000;
    new |= value;
    ptrace_set_reg_u64(pid, offset, new);
    
    return data;
}

uint64_t ptrace_get_set_reg_u16(pid_t pid, uint64_t offset, uint16_t value)
{
    uint64_t data, new;
    
    data = new = ptrace_get_reg_u64(pid, offset);
    new &= 0xffffffffffff0000;
    new |= value;
    ptrace_set_reg_u64(pid, offset, new);
    
    return data;
}

uint64_t ptrace_get_set_reg_u8 (pid_t pid, uint64_t offset, uint8_t  value)
{
    uint64_t data, new;

    data = new = ptrace_get_reg_u64(pid, offset);
    new &= 0xffffffffffffff00;
    new |= value;
    ptrace_set_reg_u64(pid, offset, new);

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
 * If we need performance, use POKEUSER and PEEKUSER,
 * exposed via ptrace_set_reg_uxx and ptrace_get_reg_u64,
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

void ptrace_print_hexdump(pid_t pid, void* address, size_t n, size_t granularity, size_t n_columns)
{
    uint8_t* buffer = calloc(1, n);
    

    ptrace_memcpy_from(pid, buffer, address, n);
     

    print_hexdump(buffer, n, granularity, n_columns, (size_t)address);
    free(buffer);
}

void ptrace_print_state(pid_t pid)
{
    struct user_aregs_struct* state = ptrace_get_aregs(pid);

    print_aregs(state);

    printf("\n\nStack: \n");
    
    ptrace_print_hexdump(pid, (void*)state->regs.rsp, 80, 8, 1);

    printf("\n\nInstruction pointer (minus one): \n");

    ptrace_print_hexdump(pid, (void*)state->regs.rip - 1, 80, 1, 8);

    free(state);
}


void ptrace_memcpy_from(pid_t pid, uint8_t* dest, void* src, size_t n)
{
    size_t amt;
    while(n != 0)
    {
        if(n >= 8)
        {
            *(uint64_t*)dest = (uint64_t)ptrace_read_u64(pid, src);
            amt = 8;
        }

        else if(n >= 4)
        {
            *(uint32_t*)dest = (uint32_t)ptrace_read_u64(pid, src); 
            amt = 4;
        }

        else if(n >= 2)
        {
            *(uint16_t*)dest = (uint16_t)ptrace_read_u64(pid, src);
            amt = 2;
        }
        else
        {
            *(uint8_t*)dest = (uint8_t)ptrace_read_u64(pid, src);
            amt = 1;
        }
        n -= amt;
        src += amt;
        dest += amt;
    }
} 

void ptrace_memcpy_to(pid_t pid, void* dest, const uint8_t* src, size_t n, uint8_t* old)
{
    /* Memcpy a `n`-sized buffer from `src` to tracee's `dest`.
     * if `old` is set, The old values are written to it.
     * A buffer of at least `n` bytes should be passed.
     * */
    
    uint64_t value;
    size_t c;

    while(n > 0)
    {
        if(n >= 8)
        {
           if(old)
                *((uint64_t*)old) = ptrace_read_write_u64(pid, dest, *((uint64_t*)src));
           else
                ptrace_write_u64(pid, dest, *((uint64_t*)src));
            
           c = 8;
        }

        else if (n >= 4)
        {
            value = ptrace_read_write_u32(pid, dest, *((uint32_t*)src));

            if(old)
                *((uint32_t*)old) = (uint32_t)value;
            
            c = 4;
        }
        else if (n >= 2)
        {
            value = ptrace_read_write_u16(pid, dest, *((uint16_t*)src));

            if(old)
                *((uint16_t*)old) = (uint16_t)value;
            
            c = 2;
        }
        else
        {
            /* n == 1 */
            value = ptrace_read_write_u8(pid, dest, *src);

            if(old)
                *old = (uint8_t)value;
            
            c = 1;
        }
        n -= c;
        src += c;
        dest += c;
        if(old)
            old += c;
    }
}

void ptrace_execute_shellcode(pid_t pid, const uint8_t* shellcode, size_t n)
{
    /*
     * Provides functionality to execute code, given in `shellcode`,
     * in the tracee. We overwrite the values at the instruction pointer
     * with our shellcode, followed by a trap instruction.
     * After overwriting, we PTRACE_CONT to continue execution, 
     * and upon hitting our trap, we swap our shellcode back again with
     * the original data.*/
    
    /*
     * Technically we can run into trouble if it just so happens to be the case that
     * rip is at the end of an executable page. Generally we only run shellcode
     * at the start of the process though, so it's not something that would occur often.
     * Still, it's advisable to write payloads that are as short as possible */

    char epilogue[] = { TRAP_OP };

    size_t final_n = n + sizeof epilogue;
    uint8_t* final_shellcode = malloc(final_n), *old_data = malloc(final_n);
    
    memcpy(final_shellcode, shellcode, n);
    memcpy(&final_shellcode[n], epilogue, sizeof epilogue);
    
    /*
     * Gotcha: after ptrace hits a trap,
     * rip will contain the location of the next instruction
     * to be executed, NOT the location of the trap instruction.
     * */

    void* rip = (void*)ptrace_get_reg_u64(pid, RIP);    
    
    ptrace_memcpy_to(pid, rip, final_shellcode, final_n, old_data);
    
    /* 
     * Execute the shellcode and wait for the trap
     * */
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    

    int status;
    waitpid(pid, &status, 0);
    
    /*
     * Restore the code that we overwrote.
     * */ 
    ptrace_memcpy_to(pid, rip, old_data, final_n, NULL);
    
    /* Restore old instruction pointer */ 
    ptrace_set_reg_u64(pid, RIP, rip);

    free(final_shellcode);
    free(old_data);
}


void ptrace_execute_shellcode_stateless(pid_t pid, const uint8_t* shellcode, size_t n)
{
    /* ptrace_execute_shellcode, but also don't clutter any registers */
    
    struct user_aregs_struct* state;
    
    state = ptrace_get_aregs(pid);

    ptrace_execute_shellcode(pid, shellcode, n);

    ptrace_set_aregs(pid, state);
    
    free(state);
}

uint64_t ptrace_execute_syscall(pid_t pid, const uint8_t* shellcode, size_t n)
{
    /*
     * Execute the code that is supplied via `shellcode`.
     * This is supposed to be a syscall stub, and the return
     * value of this function will be the return value of the
     * syscall (in rax) */


    struct user_aregs_struct* state = ptrace_get_aregs(pid);
    
    ptrace_execute_shellcode(pid, shellcode, n);
    
    uint64_t return_value = ptrace_get_reg_u64(pid, RAX);
    
    struct user_aregs_struct* state2 = ptrace_get_aregs(pid);

    ptrace_set_aregs(pid, state);

    free(state);
    return return_value;

}

