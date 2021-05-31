#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/ptrace.h>

#include "opts/opts.h"
#include "elf/elf.h"
#include "mapping.h"


/* HOOKING MECHANISM:
 * ----------------------------------------------------
 * We use a ptrace-based hooking mechanism because it gives us a lot of control.
 * We start the process, and immediately suspend it. This should be done in a
 * more or less atomic manner. After suspension, we attach to it and apply all the hooks.
 * The hooks simply consist of replacing the opcode of the target address with 0xcc (int3).
 * After this we continue execution.
 *
 * We wait for these traps to trigger, on which we retrieve the register state and change 
 * the instruction pointer to point to our hook target, as well as storing the register state in the case of HOOK_PREPEND.
 * If the hook is of mode HOOK_DETOUR, we also hijack the return address to point to 
 * the original target function. In this case, after the hook returns, the trap will be hit again, on which we will: 
 *  1. replace the overwritten 0xcc with the original opcode.
 *  2. change the instruction pointer back to the original target.
 *  3. restore the register state
 *  4. execute a single instruction with PTRACE_SINGLESTEP.
 *  5. place our 0xcc opcode back
 *  6. resume original execution.
 *
 * If the hook is of mode HOOK_REPLACE, we can skip all these steps. 
 * */


/*
 * This struct serves as the processed variant of
 * hook_target_t. It is `resolved`, in the sense
 * that the symbols have already been looked up. 
 * This struct is used to represent a hook during the actual inferior execution.
 * */

typedef struct active_hook {
    enum hook_mode mode;

    /* Addresses in the child address space */
    void* target_address;
    void* hook_address;
    
    /* Set if the addresses are backed by a symbol */
    char* target_symbol;
    char* hook_symbol;

    uint8_t replaced_opcode; /* The opcode at `target_adress` that we've overwritten. */
    size_t n_triggered; /* times triggered in total. */
    bool is_active;     /* whether this hook is placed. */
    
    /* Used to reset state when a detour is hit */ 
    struct user_aregs_struct* detour_state;

    struct active_hook* next;

} active_hook_t;


typedef struct inferior {
    pid_t pid;
    
    active_hook_t* hooks;    
    bool lib_needs_rebase; /* Whether the hooks need to be rebased relative to the library location */
    
    elf_file_t* target;
    elf_file_t* inject_lib;
    
    mapping_t** mappings;

    bool is_pie;

} inferior_t;


void inferior_reload_mappings(inferior_t*);

void inject_library(inferior_t*);
void start_hook(opts_t*);

inferior_t* create_inferior(opts_t*, elf_file_t*, elf_file_t*);
pid_t spawn_child(opts_t*);
void execute_inferior(char*, char**, char**);

void apply_hooks(inferior_t*, hook_target_t*);


active_hook_t* resolve_active_hook_bytargetaddr(active_hook_t*, void*);

void print_active_hook(active_hook_t*);
void print_active_hooks(active_hook_t*);

