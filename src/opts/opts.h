#pragma once

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


typedef struct hook_target {

    /* Offset in our target executable */
    generic_offset_t target_offset;

    /* Offset in the library */
    generic_offset_t hook_offset;
    
    struct hook_target *next;

} hook_target_t;


/* Holds all the parameters needed to hook */
typedef struct opts {
    

    /* The environment under which to run our target */
    struct {
        char* path;      /* path - will always be set */
        char** argv;     /* argv - will NOT always be set */
        char** envp;     /* envp - will NOT always be set */
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
