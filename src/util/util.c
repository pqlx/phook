#include <stdio.h>
#include <stdlib.h>

#include "util.h"

char* read_text_file(char* filename)
{
    size_t file_len;
    FILE*  handle;
    
    if( (handle = fopen(filename, "r")) == NULL)
    {
        perror("fopen");
        exit(1);
    }

    fseek(handle, 0, SEEK_END);
    file_len = ftello(handle);

    rewind(handle);
    
    /* Plus 1 for null terminator */
    char* contents = malloc(file_len + 1);
    contents[ fread(contents, 1, file_len, handle) ] = '\x00';

    fclose(handle);

    return contents;
}

uint8_t* read_binary_file(char* filename, size_t* dest_size)
{
    size_t file_len;
    FILE* handle;

    if( (handle = fopen(filename, "rb")) == NULL)
    {
        perror("fopen");
        exit(1);
    }

    fseek(handle, 0, SEEK_END);
    file_len = ftello(handle);

    rewind(handle);

    uint8_t* contents = malloc(file_len);

    fread(contents, 1, file_len, handle);

    fclose(handle);

    *dest_size = file_len;
    return contents;
}
