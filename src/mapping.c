#include <stdio.h>
#include <string.h>
#include <sys/mman.h> /* for PROT_* */

#include "util/util.h"
#include "mapping.h"


mapping_t** fetch_mappings_for(pid_t target_pid)
{
    char path[0x40] = {};
    char* contents;
    mapping_t** result;
    
    if(target_pid >= 0)
        snprintf(path, sizeof path, "/proc/%u/maps", (unsigned int)target_pid);
    else
        strcpy(path, "/proc/self/maps");

    contents = read_text_file_procfs(path);
    
    result = parse_mappings(contents);

    free(contents);
    return result; 
    
    
}

mapping_t** parse_mappings(char* to_parse)
{
    printf("TOTAL: %s\n", to_parse);
    mapping_t** result = malloc(sizeof *result);
    mapping_t* current;

    size_t n = 0;
    size_t n_mappings = 0;
    while(*to_parse != '\x00')
    {
        
        if(*to_parse == '\n')
        {
            *to_parse = '\x00';
            
            /* /proc/pid/maps can contain blank lines sometimes */
            if(to_parse[1] != '\n')
            {
                current = parse_mapping(to_parse - n);
                result = realloc(result, (n_mappings + 2) * sizeof *result);
                result[n_mappings] = current;

                n_mappings++;
                n = 0;
            }
        }
        else
        {
            n++;
        }
        to_parse++;
    }

    result[n_mappings] = NULL;
    return result;

}

mapping_t* parse_mapping(char* to_parse)
{
    /* Converts a null terminated map format line and processes it */
    
    mapping_t* result;
    char* acc;
    
    /*
     * <LOWER_BOUND>-<UPPER_BOUND> <prots><flag> <offset> <dev_hi>:<dev_lo> <inode>    <backed_by>
     */

    result = calloc(1, sizeof *result);
    
    acc = strchr(to_parse, '-');
    *acc = '\x00';
    
    result->lower_bound = (void*)strtoll(to_parse, NULL, 16); 
    to_parse = acc + 1;
    
    acc = strchr(to_parse, ' ');
    *acc = '\x00';

    result->upper_bound = (void*)strtoll(to_parse, NULL, 16);
    to_parse = acc + 1;
    
    if(*to_parse++ == 'r')
        result->prot |= PROT_READ;
    if(*to_parse++ == 'w')
        result->prot |= PROT_WRITE;
    if(*to_parse++ == 'x')
        result->prot |= PROT_EXEC;

    if(*to_parse == 'p')
        result->flags |= MAP_PRIVATE;
    if(*to_parse++ == 's')
        result->flags |= MAP_SHARED;
    
    to_parse++;
    
    acc = strchr(to_parse, ' ');
    
    *acc = '\x00';
    
    result->offset = strtoll(to_parse, NULL, 16);
    to_parse = acc + 1;
    
    to_parse[2] = '\x00';
    to_parse[5] = '\x00';
    

    result->device |= (uint16_t) ( ((uint8_t)strtol(to_parse, NULL, 16 )) << 8);
    result->device |= (uint8_t)strtol(&to_parse[3], NULL, 16);
    
    to_parse += 6;

    acc = strchr(to_parse, ' ');
    *acc = '\x00';
    
    result->inode = strtoll(to_parse, NULL, 10);
    to_parse = acc;

    while( to_parse++[1] == ' ');
    
    printf("To parse: %s\n", to_parse);
    result->backed_by = NULL;
    
    switch(*to_parse)
    {
        case '\x00':
            result->mapping_type = MAPPING_ANON;
            break;
        case '/':
            result->mapping_type = MAPPING_FILE;
            result->backed_by = strdup(to_parse);
            break;
        case '[':
            to_parse++;

            if(!strncmp(to_parse, "stack", 5))
            {
                if(to_parse[5] == ']')
                {
                    result->mapping_type = MAPPING_STACK;
                }
                else
                {
                   result->mapping_type = MAPPING_THREADSTACK;

                   *strchr(to_parse, ']') = '\x00';
                   result->thread_id = (pid_t)strtol(&to_parse[6], NULL, 10);
                }
            }
            else if(!strncmp(to_parse, "heap", 4))
                result->mapping_type = MAPPING_HEAP;
            else if(!strncmp(to_parse, "vdso", 4))
                result->mapping_type = MAPPING_VDSO;
            else if(!strncmp(to_parse, "vvar", 4))
                result->mapping_type = MAPPING_VVAR;
            else if(!strncmp(to_parse, "vsyscall", 8))
                result->mapping_type = MAPPING_VSYSCALL;
            else
                result->mapping_type = MAPPING_UNKNOWN;
            
            break;
        default:
            fputs("An error occured parsing the mapping type..", stderr);
            exit(1);

    }

    return result;
}

void free_mappings(mapping_t** mappings)
{
    mapping_t* current;

    while( (current = *mappings++) != NULL)
    {
        free(current);
    }

    free(mappings);
}

mapping_t *resolve_mapping_byaddr(const void* address, mapping_t** mappings)
{
    mapping_t* mapping;

    while( (mapping = *mappings++) != NULL)
    {
        if(address >= mapping->lower_bound && address <= mapping->upper_bound)
            return mapping;

    }
    return NULL;
}

mapping_t* resolve_mapping_byfile(const char* filename, mapping_t** mappings, bool get_first)
{
    mapping_t *mapping, *result;
    result = NULL;
    while( (mapping = *mappings++) != NULL)
    {
        if(mapping->mapping_type == MAPPING_FILE && !strcmp(mapping->backed_by, filename))
        {
            result = mapping;
            if(get_first)
                return result;
        }
    }
    return result;
}
