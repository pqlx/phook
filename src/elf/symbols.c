#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "symbols.h"

func_symbol_t* elf_read_func_symbols_fd(int fd)
{
    /* Support reading from a raw fd directly.
     * This way we can have a single handle, 
     * Instead of having to reopen the file, we can just lseek 
     * */

    Elf       *elf;
    Elf_Scn   *section = NULL;
    GElf_Shdr section_header;
    bool      found;
    func_symbol_t  *result;

    elf_version(EV_CURRENT);

    if ( (elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        perror("elf_begin");
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

    if(!found)
        goto end;
    
    
    Elf_Data *data;
    size_t n_entries;
    
    /* Fetch the symbol section we found earlier */ 
    data = elf_getdata(section, NULL);
    n_entries = section_header.sh_size / section_header.sh_entsize;
    
    func_symbol_t *current;
    result = NULL;
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
             current->next = result;
             result = current;
        }
    }
    
    end:
    elf_end(elf);

    return result;
}

func_symbol_t* elf_read_func_symbols_file(char* filename)
{
    /*
     * Higher level interface to elf_read_func_symbols_fd
     * Use this if you don't need to keep a handle to the ELF.
     * */

    int fd;
    func_symbol_t* results;
    if( (fd = open(filename, O_RDONLY)) < 0)
    {
        perror("open");
        return NULL;
    }

    if( (results = elf_read_func_symbols_fd(fd)) == NULL)
        perror("elf_read_func_symbols_fd");
    
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
