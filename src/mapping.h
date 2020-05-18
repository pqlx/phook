#pragma once

#include <stdlib.h>
#include <stdint.h>

/*
 * C-representation of an entry in the output of /proc/pid/maps.
 */

typedef struct mapping {
    void* lower_bound;
    void* upper_bound;
    int prot; /* PROT_READ / PROT_WRITE / PROT_EXEC or combination */
    int flags; /* MAP_PRIVATE / MAP_SHARED */
    size_t offset;
    uint16_t device;
    uint32_t inode;
    
    enum mapping_types {
        MAPPING_FILE        = 0x00,
        MAPPING_HEAP        = 0x01,
        MAPPING_STACK       = 0x02,
        MAPPING_THREADSTACK = 0x03,
        MAPPING_ANON        = 0x04,
        MAPPING_VVAR        = 0x05,
        MAPPING_VDSO        = 0x06,
        MAPPING_VSYSCALL    = 0x07,
        MAPPING_UNKNOWN     = 0x08

    } mapping_type; 
    
    union {
        char* backed_by; /* for MAPPING_FILE */ 
        pid_t thread_id; /* for MAPPING_THREADSTACK */
    };

} mapping_t;

mapping_t** fetch_mappings_for(pid_t);
mapping_t** parse_mappings(char*);
mapping_t*  parse_mapping(char*);

mapping_t* resolve_mapping_byaddr(const void*, const mapping_t**);
