#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>


#include "hook.h"
#include "util/trace.h"
#include "util/richtext.h"
#include "util/util.h"


inferior_t* create_inferior(opts_t* opts, elf_file_t* target, elf_file_t* inject_lib)
{
    pid_t child_pid = spawn_child(opts);
    int status;
    inferior_t* result;

    waitpid(child_pid, &status, 0);

    result = calloc(1, sizeof *result);
    result->pid = child_pid;
    result->target = target;
    result->inject_lib = inject_lib;
    result->mappings = fetch_mappings_for(child_pid);
    return result;

}

void inferior_reload_mappings(inferior_t* inferior)
{
    free_mappings(inferior->mappings);
    free(inferior->mappings);
    inferior->mappings = fetch_mappings_for(inferior->pid);
}

bool inferior_rebase_lib(inferior_t* inferior)
{
    mapping_t* lib_mapping;
    inferior_reload_mappings(inferior);
    

    if( (lib_mapping = resolve_mapping_byfile(inferior->inject_lib->path, inferior->mappings, true)) == NULL)
    {
        return false;
    }

    active_hook_t* hook = inferior->hooks;
    
    while(hook)
    {
        hook->hook_address += (size_t)lib_mapping->lower_bound;

        hook = hook->next;
    }

    return true;


}

void inject_library(inferior_t* inferior)
{
    /* Try to inject our target library into our child.
     * The child is still in "suspended" state at this point.
     * We overwrite the instructions at $rip to our shellcode,
     * which calls _dl_start(inferior->inject_lib->path);
     * We place an int3 instruction at the end, so we can 
     * load the correct offsets for our hooks.
     *
     * This method is preferrable to something like LD_PRELOAD.
     * This is a much more portable solution.
     *
     * This method will only work for binaries that either have the linker loaded,
     * or have a _dl_open symbol statically linked. if neither of these constraints
     * are satisfieds we will need to manually load our ELF.
     * */
    
}

inferior_t* do_hook_static (opts_t* opts, elf_file_t* target, elf_file_t* inject_lib)
{
    /* Not yet implemented */
    
    return NULL;
}

inferior_t* do_hook_dynamic(opts_t* opts, elf_file_t* target, elf_file_t* inject_lib)
{
    /*
     * Easiest course of action: simply inject our library
     * using LD_PRELOAD.
     * */

    char** envp = opts->target_executable.envp;
    
    bool is_resolved = false;

    /*
     * If LD_PRELOAD is already set, append to string.. */ 
    while(*envp)
    {

        if(!strncmp(*envp, "LD_PRELOAD=", 11))
        {
            size_t current_preload_length = strlen(*envp);

            /* Plus one for ' ' plus one for null byte = + 2*/
            size_t total_preload_length = current_preload_length + strlen(inject_lib->path) + 2;
            
            *envp = realloc(*envp, total_preload_length);

            (*envp)[current_preload_length] = ' ';
            strcpy(&((*envp)[current_preload_length + 1]), inject_lib->path);
            
            is_resolved = true;
            
            break;
            
        }
        envp++;
    }

    /* Else, simply append to array. */
    if(!is_resolved)
    {
        /* 11 for "LD_PRELOAD=", 1 for null byte */
        char* ld_preload = malloc(11 + strlen(inject_lib->path) + 1); 
        sprintf(ld_preload, "LD_PRELOAD=%s", inject_lib->path);
        
        opts->target_executable.envp = strarray_append(opts->target_executable.envp, ld_preload);
    }
    
    inferior_t* inferior = create_inferior(opts, target, inject_lib);
    
    return inferior;
}


void do_hook_loop(inferior_t* inferior)
{
    int status;
    
    active_hook_t* active_hook;
    void* rip;
    uint8_t prev_op;

    while(true)
    {
        waitpid(inferior->pid, &status, 0); 
        
        
        if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        {
                     
            if(WIFEXITED(status))
            {
                puts("Child has terminated.");
                puts("Terminating..");
                exit(1);
            }
            else
            {
                printf("Unknown status %d received..", status);
                ptrace(PTRACE_CONT, inferior->pid, NULL, NULL);
                continue;
            }
        }   
        
        /* At this point our library base address might 
         * have not been resolved yet.
         * If this is the case, we do it now, 
         * and add it to ever hook target address 
         * */

        if(inferior->lib_needs_rebase && !inferior_rebase_lib(inferior))
        {
           puts("Could not rebase library.");
           puts("Terminating..");
           exit(1);

        }
        else
        {
            inferior->lib_needs_rebase = false;
        }
        /* Fetch the tracee's instruction pointer to see which hook to trigger */
        rip = (void*)ptrace_get_reg_u64(inferior->pid, RIP) - 1;
        
        /* It should be noted that at this point, the register
         * state is set in such a way that the instruction pointer
         * is located at the instruction AFTER our trap opcode.
         * to get the correct hook address, we should subtrace 1 (size of int3)
         * from it. 
         * */

        /* Sanity check: If this check fails, then our SIGTRAP
         * has been triggered by something else, which is not what
         * we want. */ 
        
        prev_op = (uint8_t)ptrace_read_u64(inferior->pid, rip);

        if( prev_op != TRAP_OP)
        {
            printf("Major warning: byte at %p is not %.2x but %.2x\n", rip, TRAP_OP, prev_op);
            ptrace_print_state(inferior->pid); 
            continue;
        }

        if( (active_hook = resolve_active_hook_bytargetaddr(inferior->hooks, rip)) == NULL)
        {
            printf("%p: could not find a hook here...\n", rip - 1);
            continue;
        } 
        
        active_hook->n_triggered++;
        
        void* rsp;

        switch(active_hook->mode)
        {
            case HOOK_REPLACE:
               /* This case is the simplest: 
                * we simply change the instruction pointer
                * to our hook target */

                ptrace_set_reg_u64(inferior->pid, RIP, active_hook->hook_address);
                break;
            case HOOK_DETOUR:
                /* This case is more complicated.
                 * There are now two ways this trap can be hit:
                 *  1. Our hook needs to be called
                 *  2. Our hook has been called, and original execution should resume
                 *
                 * We differ this based on the amount of times 
                 * this hook has been hit.
                 * if everything goes as expected: an odd amount of hits signifies
                 * option 1, and an even amount signifies option 2.
                 *
                 * */
                
                /* Odd amount -> option 1 */
                if(active_hook->n_triggered & 1)
                {
                    /* Save our original register state.
                    * We will restore this state in option 2. */
                    
                    active_hook->detour_state = ptrace_get_aregs(inferior->pid);                   
                    
                    /* Since we want to return to our
                     * original function to resume execution,
                     * we effectively need to emulate a `call` instruction
                     * in our child:
                     * 
                     * sub rsp, 8
                     * mov qword ptr [rsp], rip
                     * jmp hook
                     *
                     * A minor gotcha: the `rip` should
                     * be a pointer to our original trap op,
                     * not to the instruction after it.
                     * */
                    
                    /* push rip */
                    rsp = (void*)ptrace_get_reg_u64(inferior->pid, RSP);
                    ptrace_get_set_reg_u64(inferior->pid, RSP, (uint64_t)(rsp - 8));
                    ptrace_read_write_u64(inferior->pid, rsp - 8, (uint64_t)rip);

                    /* jmp hook */
                    ptrace_set_reg_u64(inferior->pid, RIP, active_hook->hook_address);


                }

                /* Even amount -> option 2 */
                else
                {
                    /* Since we've overwritten the first byte of the hook target
                     * with the trap operation, we will need to:
                     *  1. place it back
                     *  2. "jmp" to it
                     *  3. execute the instruction
                     *  4. place the trap op back
                     *  */
                    
                    /* Position rip to point to our trap op */
                    active_hook->detour_state->regs.rip -= 1;
                    
                    /* Place back original opcode */
                    ptrace_read_write_u8(inferior->pid, (void*)active_hook->detour_state->regs.rip, active_hook->replaced_opcode);
                
                    /* Restore the state */
                    ptrace_set_aregs(inferior->pid, active_hook->detour_state);
                    
                    /* Execute the first instruction again */
                    ptrace(PTRACE_SINGLESTEP, inferior->pid, 0, 0);
                    
                    /* Restore trap op */ 
                    ptrace_read_write_u8(inferior->pid, (void*)active_hook->detour_state->regs.rip, TRAP_OP);
                    
                    /* We don't need it anymore - properly clean it up */
                    free(active_hook->detour_state);
                    active_hook->detour_state = NULL;

                    
                            
                }
        }
        ptrace(PTRACE_CONT, inferior->pid, NULL, NULL);

    }
}
void start_hook(opts_t* opts)
{
    elf_file_t *target, *inject_lib;

    target     = elf_file_fill(opts->target_executable.path);
    inject_lib = elf_file_fill(opts->to_inject_path);
    
    inferior_t* (*hook_func)(opts_t*, elf_file_t*, elf_file_t*);

    if(target == NULL || inject_lib == NULL)
    {
        fputs("Terminating...\n", stderr);
        exit(1);
    }
    
    if(!resolve_hook_targets(opts->hooks, target, inject_lib))
    {
        fputs("Terminating...\n", stderr);
        exit(1);
    }
    

    switch(target->info->link_type)
    {
        case LINK_DYNAMIC:
            hook_func = do_hook_dynamic;
            break;
        case LINK_STATIC:
            hook_func = do_hook_static;
            break;
    }
    
    inferior_t* inferior;

    if( (inferior = hook_func(opts, target, inject_lib)) == NULL)
    {
        printf("Something went terribly wrong....\n\n");
        exit(1); 
    };

    apply_hooks(inferior, opts->hooks);
    

    ptrace(PTRACE_O_TRACEEXIT, inferior->pid, NULL, NULL);    
    ptrace(PTRACE_CONT, inferior->pid, NULL, NULL);
  
    do_hook_loop(inferior);
}


void write_hook(inferior_t* inferior, active_hook_t* hook)
{
    hook->replaced_opcode = (uint8_t)ptrace_read_write_u8(inferior->pid, hook->target_address, TRAP_OP);
}

void apply_hooks(inferior_t* inferior, hook_target_t* pending)
{

    mapping_t *target_first_mapping, *target_last_mapping, *lib_mapping;
    
    if( (target_first_mapping = resolve_mapping_byfile(inferior->target->path, inferior->mappings, true)) == NULL)
    {
        fprintf(stderr, "Could not resolve executable mapping in child [begin].\n");
        exit(1);   
    }

    if( (target_last_mapping  = resolve_mapping_byfile(inferior->target->path, inferior->mappings, false)) == NULL)
    {
        fprintf(stderr, "Could not resolve executable mapping in child [end].\n");
    }
    
    

    inferior->lib_needs_rebase = !(lib_mapping = resolve_mapping_byfile(inferior->inject_lib->path, inferior->mappings, true));
    
    void *target_base = target_first_mapping->lower_bound;
    void *target_end  = target_last_mapping->upper_bound;

    while(pending)
    {
        /* Sanity check: There's not supposed to be any OFFSET_SYMBOL `target_offset`s */

        if(pending->target_offset.type == OFFSET_SYMBOL)
        {
            fprintf(stderr, "apply_hooks: symbol <%s> still found in targets (not resolved).\n", pending->target_offset.symbol);
            exit(1);
        }
        
        if(pending->hook_offset.type == OFFSET_SYMBOL)
        {
            fprintf(stderr, "apply_hooks: symbol <%s> still found in hooks (not resolved).\n", pending->hook_offset.symbol);
            exit(1);
        }

        void* target_address = target_base + pending->target_offset.raw;
        
        if(target_address < target_base || target_address > target_end)
        {
            fprintf(stderr, "Target is mapped from %p - %p -- hook offset resolves out of bounds: to %p\n", target_base, target_end, target_address);
            
            exit(1);
        }

        active_hook_t* current;
        current = calloc(1, sizeof *current);
        
        current->mode           = pending->mode;
        current->target_address = target_address;
        current->target_symbol  = pending->target_offset.symbol == NULL ? NULL : strdup(pending->target_offset.symbol);

        current->hook_address = (void*)(pending->hook_offset.raw + (lib_mapping ? lib_mapping->lower_bound : 0));
        
        current->hook_symbol  = pending->hook_offset.symbol == NULL ? NULL : strdup(pending->hook_offset.symbol);

        current->n_triggered = 0; 
        
        write_hook(inferior, current);
        
        current->is_active = true;

        current->next = inferior->hooks;
        inferior->hooks = current;
        pending = pending->next;
    }

}

pid_t spawn_child(opts_t* opts)
{
    pid_t result;
    if( (result = fork()) == 0)
    {
        execute_inferior(
                    opts->target_executable.path,
                    opts->target_executable.argv,
                    opts->target_executable.envp);
            
    }

    return result;
}

void execute_inferior(char* path, char** argv, char** envp)
{
    /*
     * To be called in the child process.
     * */

    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve(path, argv, envp);
}


active_hook_t* resolve_active_hook_bytargetaddr(active_hook_t* hook, void* address)
{
    while(hook)
    {
        if(address == hook->target_address)
            return hook;
        hook = hook->next;
    }
    return NULL;
}

void print_active_hook(active_hook_t* hook)
{
    printf("Hook at:    %p", hook->target_address);
    if(hook->target_symbol)
        printf(" (%s)", hook->target_symbol);
    putchar('\n');

    printf("Points to:  %p", hook->hook_address);
    if(hook->hook_symbol)
        printf(" (%s)", hook->hook_symbol);
    
    puts("\n");

    printf("Is enabled: %s" TERM_RESET "\n", hook->is_active ? TERM_COLOR_GREEN "TRUE" : TERM_COLOR_RED "FALSE");
    printf("Replaced opcode: %.2x\n", hook->replaced_opcode);
}

void print_active_hooks(active_hook_t* hook)
{
    while(hook)
    {
        print_active_hook(hook);
        putchar('\n');
        hook = hook->next;
    }
}


