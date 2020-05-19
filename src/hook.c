#include <stdio.h>
#include <stdlib.h>

#include "hook.h"

void start_hook(opts_t* opts)
{
    elf_file_t *target, *inject_lib;
    
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

}
