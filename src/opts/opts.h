#pragma once

#include <stdbool.h>

#include "../elf/elf.h"

typedef struct generic_offset {
    
    enum {
        OFFSET_RAW    = 0x00,
        OFFSET_SYMBOL = 0x01
    } type;

    union {
        char* symbol;
        size_t raw;
    };

} generic_offset_t;


enum hook_mode {
    HOOK_PREPEND  = 0x00, /* After the hook is done, execute original function */
    HOOK_REPLACE = 0x01  /* After the hook is done, return to caller and skip original execution */
};

typedef struct hook_target {
    
    enum hook_mode mode;

    /* Offset in our target executable */
    generic_offset_t target_offset;

    /* Offset in the library */
    generic_offset_t hook_offset;
    
    struct hook_target* next;

} hook_target_t;


/* Holds all the parameters needed to hook */
typedef struct opts {
    

    /* The environment under which to run our target */
    struct {
        char* path;      /* path - will always be set */
        char** argv;     /* argv - will NOT always be set */
        char** envp;     /* envp - will NOT always be set */
        
        generic_offset_t _dl_open_offset; /* as of now we NEED a _dl_open function to be present for statically linked binaries. */
    } target_executable;

    /* Path of the library we will inject; 
     * This will contain all our hooks */
    char* to_inject_path;

    /* Hooks, tells us which functions we should redirect to where */
    hook_target_t *hooks;

} opts_t;

/* Read options from json file */
opts_t *read_opts_file(char*);
opts_t *read_opts_json(char*);

void free_opts(opts_t*);


generic_offset_t* resolve_generic_offset(generic_offset_t*, const func_symbol_t*);
bool resolve_hook_targets(hook_target_t*, const elf_file_t*, const elf_file_t*);
