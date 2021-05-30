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

    size_t n_read;

    if( (n_read = fread(contents, 1, file_len, handle)) != file_len)
    {
        perror("fread");
        exit(1);
    }

    contents[n_read] = '\x00';

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
        printf("File: %s\n", filename);
        exit(1);
    }

    while( (result[n_read++] = fgetc(handle)) != EOF)
    {
        if(n_read % 0x100)
        {
            result = realloc(result, 0x100 + n_read + 1); 
        }
    }

    result[n_read - 1] = '\x00';
    result = realloc(result, n_read);
    
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

    if(fread(contents, 1, file_len, handle) != file_len)
    {
        perror("fopen");
        exit(1);
    }

    fclose(handle);

    *dest_size = file_len;
    return contents;
}

char** strarray_append(char** array, char* to_append)
{
    size_t n = 0;

    while(array[n])
        n++;
    
    array = realloc(array, (n + 2) * sizeof(*array));

    array[n] = to_append;
    array[n + 1] = NULL;
    return array; 
}

void strarray_free(char** array)
{
    while(*array)
        free(*array++);
}

void print_hexdump(uint8_t* bytes, size_t n, size_t granularity, size_t n_columns, size_t base_addr)
{
    /* Print a nice hexdump of a target buffer.
     * granularity: amount of bytes per element
     * n_columns: amount of elements per row
     * */
    
    /* Round down to previous power of two */  
    while(granularity & (granularity - 1))
        granularity &= (granularity - 1);

    /* Round to lowest multiple of `granularity` */ 
    n &= ~(granularity - 1);
    
    size_t n_values = n / granularity;
     
    printf("%.16llx: ", (long long unsigned)base_addr);

    for(size_t i = 0; i < n_values; ++i)
    {
        printf("0x");
        for(int j = 0; j < granularity; ++j)
        {
            printf("%.2hhx", bytes[(i + 1)*granularity - (j + 1)]);
        }
        putchar(' ');
        
        if( (i + 1) % n_columns == 0)
        {
            printf("\n%.16llx: ", (unsigned long long)(base_addr + (i + 1) * granularity));
        }

    }

}
