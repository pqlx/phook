#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>

#include "hook.h"
#include "util/trace.h"

pid_t spawn_child(opts_t*);
void execute_inferior(char*, char**, char**);

void apply_hooks(inferior_t*, hook_target_t*);

void start_hook(opts_t* opts)
{
    elf_file_t *target, *inject_lib;
    // active_hook_t* hooks;

    target     = elf_file_fill(opts->target_executable.path);
    inject_lib = elf_file_fill(opts->to_inject_path);
    
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
    
    pid_t child_pid = spawn_child(opts);
    
    int status;
    
    /* catch at execve() */
    waitpid(child_pid, &status, 0);    
    
    inferior_t* inferior;

    inferior = calloc(1, sizeof *inferior);
    
    inferior->pid = child_pid;
    
    inferior->target = target;
    inferior->inject_lib = inject_lib;
    
    inferior->mappings = fetch_mappings_for(inferior->pid);

    if(target->info->link_type == LINK_DYNAMIC)
    {
        apply_hooks(inferior, opts->hooks);
    }
    else
    {
        fprintf(stderr, "There is no support for statically linked executables as of now.\n");
        exit(1);
    }

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

}

void write_hook(inferior_t* inferior, active_hook_t* hook)
{
    hook->replaced_opcode = (uint8_t)ptrace_write_u8(inferior->pid, hook->target_address, TRAP_OP);
}

void apply_hooks(inferior_t* inferior, hook_target_t* pending)
{

    mapping_t *target_first_mapping, *target_last_mapping;
    
    if( (target_first_mapping = resolve_mapping_byfile(inferior->target->path, inferior->mappings, true)) == NULL)
    {
        fprintf(stderr, "Could not resolve executable mapping in child [begin].\n");
        exit(1);   
    }

    if( (target_last_mapping  = resolve_mapping_byfile(inferior->target->path, inferior->mappings, false)) == NULL)
    {
        fprintf(stderr, "Could not resolve executable mapping in child [end].\n");
    }
            
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
        
        /* This one is currently not based, we will do that once the first trap is hit. */
        current->hook_address = (void*)pending->hook_offset.raw;
        
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
