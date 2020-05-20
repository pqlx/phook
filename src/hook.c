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

    while(true)
    {
        waitpid(inferior->pid, &status, 0); 
        
        if(inferior->lib_needs_rebase && !inferior_rebase_lib(inferior))
        {
           printf("Could not rebase library.\n");
           exit(1);

        }

        print_active_hooks(inferior->hooks);

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
