#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "opts.h"



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

    opts_t *opts = read_opts_file(config_file);
}
