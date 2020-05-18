#pragma once

#include <elf.h>



typedef struct func_symbol {
    char* identifier;
    Elf64_Addr value;

    struct func_symbol *next;

} func_symbol_t;


/* "Processed" ELF */

typedef struct proc_elf {
    func_symbol_t* func_symbols;
} proc_elf_t;


proc_elf_t* elf_process_file(char*);
proc_elf_t* elf_process_fd(int);

void print_func_symbol(const func_symbol_t*);
void print_func_symbols(const func_symbol_t*);

func_symbol_t *resolve_func_symbol_byid(const func_symbol_t*, char*);
func_symbol_t *resolve_func_symbol_byvalue(const func_symbol_t*, Elf64_Addr);

void free_func_symbols(func_symbol_t*);
