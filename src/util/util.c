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

char* read_text_file_procfs(char* filename)
{
    /*
     * Since procfs files do not have a size, We'll need to
     * read it the clumsy way. */

    char* result = malloc(0x100 + 1);
    size_t n_read = 0;
    FILE* handle;
    
    if( (handle = fopen(filename, "r")) == NULL)
    {
        perror("fopen");
        exit(1);
    }

    while( (result[n_read++] = fgetc(handle)) != EOF)
    {
        if(n_read % 0x100)
        {
            result = realloc(result, 0x100 + n_read + 1); 
        }
    }

    result[n_read] = '\x00';
    result = realloc(result, n_read + 1);
    
    return result;
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
