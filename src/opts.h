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
    generic_offset_t hook_lib_offset;

} hook_target_t;


/* Holds all the parameters needed to hook */
typedef struct opts {
    

    /* The environment under which to run our target */
    struct {
        char* path;
        char** argv;
        char** envp;
    } target_executable;

    /* Path of the library we will inject; 
     * This will contain all our hooks */
    char* hooking_lib_path;

    /* Hooks, tells us which functions we should redirect to where */
    hook_target_t *hooks;
    size_t n_hooks;

} opts_t;

/* Read options from json file */
opts_t *read_opts_file(char*);
opts_t *read_opts_json(char*);
