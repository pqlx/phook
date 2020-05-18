#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "opts/opts.h"
#include "elf/parse.h"

void usage(void)
{
    fprintf(stderr, 
            "Usage: ./phook --config-file PATH-TO-CONFIG\n"
           );
    
    exit(1);
}


int main(int argc, char** argv)
{
    char *config_file;

    if( argc < 3 || strcmp(argv[1], "--config-file"))
        usage();


    config_file = argv[2];

    read_opts_file(config_file);
    
    proc_elf_t *elf;
    
    elf = elf_process_file("./phook"); 
    func_symbol_t *main_symbol = resolve_func_symbol_byid(elf->func_symbols, "main"); 
    print_func_symbol(main_symbol);
    
    printf("linkage type: %d\n", elf->link_type);

    return 0;

}
