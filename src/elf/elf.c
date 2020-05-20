#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "elf.h"

elf_file_t* elf_file_fill(char* path)
{
    elf_file_t* result;
    result = calloc(1, sizeof *result);

    if( (result->path = realpath(path, NULL)) == NULL)
    {
        free(result);
        perror("realpath");
        printf("File: %s\n", path);
        return NULL;
    }
        
    result->info = elf_process_file(result->path);

    return result;
}

void elf_file_free(elf_file_t* elf)
{
    free_func_symbols(elf->info->func_symbols);
    free(elf->info->interpreter);
    free(elf->info);

    free(elf->path);
}

func_symbol_t* get_symbols_from_section(Elf* elf, GElf_Shdr* shdr, Elf_Scn* section)
{
    Elf_Data* data;
    size_t n_entries;
    
    data = elf_getdata(section, NULL);

    n_entries = shdr->sh_size / shdr->sh_entsize;

    func_symbol_t* result = NULL, *current;
    for(int i = 0; i < n_entries; ++i)
    {
        GElf_Sym symbol;
        gelf_getsym(data, i, &symbol);
        
         if( ELF64_ST_TYPE(symbol.st_info) == STT_FUNC && symbol.st_value != 0)
         {
             current = calloc(1, sizeof *current);
             
             /* Make a copy of the string in the symbol table */
             current->identifier = strdup( 
                     elf_strptr(elf, shdr->sh_link, symbol.st_name)
                     );
                
             current->value = symbol.st_value;
             current->next = result;
             result = current;
         }

    }

    return result;
}

elf_info_t* elf_process_fd(int fd)
{
    /* Support reading from a raw fd directly.
     * This way we can have a single handle, 
     * Instead of having to reopen the file, we can just lseek 
     * */


    Elf       *elf;
    Elf_Scn   *section = NULL, *symtab = NULL, *dynsym = NULL;
    GElf_Shdr section_header;
    
    elf_info_t* result = NULL;
   
    elf_version(EV_CURRENT);

    if ( (elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        fprintf(stderr, "elf_begin failed: %s", elf_errmsg(-1));
        return NULL;   
    }
    
    while( (section = elf_nextscn(elf, section)) != NULL)
    {
        gelf_getshdr(section, &section_header); 
        if(!symtab && section_header.sh_type == SHT_SYMTAB)
        {
            symtab = section;
        }

        else if(!dynsym && section_header.sh_type == SHT_DYNSYM)
        {
            dynsym = section;
        }
        if(dynsym && symtab)
            break;
    }
    
    result = calloc(1, sizeof *result); 
    

    func_symbol_t* symbols;
    
    gelf_getshdr(dynsym, &section_header);

    if(dynsym)
        result->func_symbols = get_symbols_from_section(elf, &section_header, dynsym);
    
    gelf_getshdr(symtab, &section_header);
    symbols = get_symbols_from_section(elf, &section_header, symtab);
    if(symtab)
    {
        if(!result->func_symbols)
            result->func_symbols = symbols;
        else
            result->func_symbols->next = symbols;
    }
   
    GElf_Phdr program_header;
    size_t phdrnum;
     
    elf_getphdrnum(elf, &phdrnum);
    
    result->link_type = LINK_STATIC;
    for(size_t i = 0; i < phdrnum; ++i)
    {
        gelf_getphdr(elf, i, &program_header);

        /* The ELF file is dynamically loaded if it contains a PT_INTERP segment.
         * If this segment exists, it also contains an offset in the file to the interpreter string.
         * this offset is given in program_header.p_offset */

        if(program_header.p_type == PT_INTERP)
        {
            result->link_type = LINK_DYNAMIC;
            
            /* Sanity check */

            if(program_header.p_memsz > 0x100)
            {
                fprintf(stderr, "PT_INTERP phdr.p_memsz > 0x100.\n");
                exit(1);
            }

            /* Read the interpreter string. */
            char* interpreter = malloc(program_header.p_memsz + 1);
            lseek(fd, program_header.p_offset, SEEK_SET);
            interpreter[read(fd, interpreter, program_header.p_memsz)] = '\x00'; 
            
            if ( (result->interpreter = realpath(interpreter, NULL) ) == NULL)
            {
                perror("realpath");
                fprintf(stderr, "File: %s\n", interpreter);
                exit(1);
            }

            free(interpreter); 
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
