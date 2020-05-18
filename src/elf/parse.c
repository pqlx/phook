#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "parse.h"

elf_file_t* elf_file_fill(char* path)
{
    elf_file_t* result;
    result = calloc(1, sizeof *result);

    if( (result->path = realpath(path, NULL)) == NULL)
    {
        free(result);
        perror("realpath");
        return NULL;
    }
    
    
    result->info = elf_process_file(result->path);

    return result;
}

elf_info_t* elf_process_fd(int fd)
{
    /* Support reading from a raw fd directly.
     * This way we can have a single handle, 
     * Instead of having to reopen the file, we can just lseek 
     * */


    Elf       *elf;
    Elf_Scn   *section = NULL;
    GElf_Shdr section_header;
    bool      found;
    
    elf_info_t* result = NULL;
   
    elf_version(EV_CURRENT);

    if ( (elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        fprintf(stderr, "elf_begin failed: %s", elf_errmsg(-1));
        return NULL;   
    }
    
    /* Loop over sections until a symbol section is found */
    found  = false;
    while( (section = elf_nextscn(elf, section)) != NULL)
    {
        gelf_getshdr(section, &section_header); 
        if(section_header.sh_type == SHT_SYMTAB)
        {
            found = true;
            break;
        }
    }
    


    result = calloc(1, sizeof *result); 
    if(found)
    { 
  
        Elf_Data *data;
        size_t n_entries;
    
        /* Fetch the symbol section we found earlier */ 
        data = elf_getdata(section, NULL);
        n_entries = section_header.sh_size / section_header.sh_entsize;
   

        func_symbol_t *current;
        for(int i = 0; i < n_entries; ++i)
        {
            GElf_Sym symbol;
            gelf_getsym(data, i, &symbol);
        
            /* Check if the current symbol is 1. a function and 2. not a relocation,
            * i.e the code is not just a procedure linkage table stub 
            * */
            if( ELF64_ST_TYPE(symbol.st_info) == STT_FUNC && symbol.st_value != 0)
            {
                current = calloc(1, sizeof *current);
             
                /* Make a copy of the string in the symbol table */
                current->identifier = strdup( 
                     elf_strptr(elf, section_header.sh_link, symbol.st_name)
                     );
             
                current->value = symbol.st_value;
                current->next = result->func_symbols;
                result->func_symbols = current;
            }
        }
    }
   
    GElf_Phdr program_header;
    size_t phdrnum;
     
    elf_getphdrnum(elf, &phdrnum);
    
    result->link_type = LINK_STATIC;
    for(size_t i = 0; i < phdrnum; ++i)
    {
        gelf_getphdr(elf, i, &program_header);

        if(program_header.p_type == PT_INTERP)
        {
            result->link_type = LINK_DYNAMIC;
            break;
        }
            
    }

    
    elf_end(elf);

    return result;
}

elf_info_t* elf_process_file(char* filename)
{
    /*
     * Higher level interface to elf_read_func_symbols_fd
     * Use this if you don't need to keep a handle to the ELF.
     * */

    int fd;
    elf_info_t* results;
    if( (fd = open(filename, O_RDONLY)) < 0)
    {
        perror("open");
        return NULL;
    }

    if( (results = elf_process_fd(fd)) == NULL)
    {
        printf("parsing \"%s\" failed.\n", filename);
        return NULL;
    }
    
    close(fd);

    return results;
    
}


void print_func_symbol(const func_symbol_t* symbol)
{
    printf("%s @ 0x%lx\n", symbol->identifier, symbol->value);
}

void print_func_symbols(const func_symbol_t* symbol)
{
    while(symbol)
    {
        print_func_symbol(symbol);
        symbol = symbol->next;
    }
}

func_symbol_t *resolve_func_symbol_byid(const func_symbol_t* symbol, char* name)
{
    while(symbol)
    {
        if(!strcmp(symbol->identifier, name))
            return (func_symbol_t*)symbol;
        symbol = symbol->next;
    }
    return NULL;
}

func_symbol_t *resolve_func_symbol_byvalue(const func_symbol_t* symbol, Elf64_Addr value)
{
    while(symbol)
    {
        if(symbol->value == value)
            return (func_symbol_t*)symbol;
        symbol = symbol->next;
    }
    return NULL;
}

void free_func_symbols(func_symbol_t* symbol)
{
    func_symbol_t *next;
    while(symbol)
    {
        next = symbol->next;
        
        free(symbol->identifier);
        free(symbol);

        symbol = next;
    }
}
