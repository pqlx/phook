#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "opts.h"
#include "../lib/cjson/cJSON.h"
#include "../util/util.h"
#include "../util/richtext.h"


opts_t *read_opts_file(char* filename)
{
    char* json;
    opts_t *result;
 
    json = read_text_file(filename);
    result = read_opts_json(json);

    free(json);

    return result;
}

#define json_parse_generic_offset(DEST, ENTRY, IDX) \
    do { \
        is_string = cJSON_IsString(ENTRY); \
        if(!is_string && !cJSON_IsNumber(ENTRY)) \
        parsing_error("\"hooks\", element `%lu`: \"%s\" either missing or not [string, number].\n", IDX, (ENTRY)->string); \
        if(is_string) \
        { \
            if(!strncmp( (ENTRY)->valuestring, "0x", 2)) \
            { \
                is_string = false; \
                offset_value = strtoll(&(ENTRY)->valuestring[2], NULL, 16); \
            } \
            else \
                offset_value = (size_t)((ENTRY)->valuestring); \
        } \
        else \
            offset_value = (size_t) ((ENTRY)->valueint); \
        (DEST)->type = is_string ? OFFSET_SYMBOL : OFFSET_RAW; \
        if(is_string) \
            (DEST)->symbol = strdup((char*)offset_value); \
        else \
            (DEST)->raw = offset_value; \
    } while(0);

opts_t *read_opts_json(char* json_buf)
{
    cJSON*  parsed;
    cJSON*  target;
    cJSON*  exec_list;
    cJSON*  env;

    size_t  iterator_idx;
    cJSON*  iterator;
    
    cJSON*  hook_entry;
    cJSON*  acc;
    
    bool is_string;
    
    char* real_path;
    opts_t* result;
     
    #define parsing_error(err, ...) \
        do { \
        fprintf(stderr, "An error occurred parsing JSON: " err, ##__VA_ARGS__); \
        exit(1); } while(0);

    if ( (parsed = cJSON_Parse(json_buf)) == NULL)
    {
        parsing_error("Invalid JSON file.\n");
    }
    
    if ( !cJSON_IsObject(parsed))
    {
        parsing_error("Root element not [object].\n");
    }

    result = calloc(1, sizeof *result);
    
    if(!cJSON_IsObject(target = cJSON_GetObjectItemCaseSensitive(parsed, "target_executable")))
    {
        parsing_error("\"target_executable\" either missing or not [object].\n");
    }
    
    exec_list = cJSON_GetObjectItemCaseSensitive(target, "exec");

    if(cJSON_IsString(exec_list))
    {
        if( (result->target_executable.path = realpath(exec_list->valuestring, NULL)) == NULL)
        {
            perror("realpath");
            fprintf(stderr, "File: %s\n", exec_list->valuestring);
            exit(1);
        }
        result->target_executable.argv = malloc(sizeof(char*) * 2);
        result->target_executable.argv[0] = strdup(result->target_executable.path);
        result->target_executable.argv[1] = NULL;
    }

    else if (cJSON_IsArray(exec_list))
    {
        iterator_idx = 0;
        
        /* Enough space for all elements plus a NULL terminator */
        result->target_executable.argv = malloc( (cJSON_GetArraySize(exec_list) + 1) * sizeof(char*) );

        cJSON_ArrayForEach(iterator, exec_list)
        {
            if(!cJSON_IsString(iterator))
            {
                parsing_error("\"exec\": element `%lu` not [string].\n", iterator_idx);
            }
            
            result->target_executable.argv[iterator_idx] = strdup(iterator->valuestring);
            iterator_idx++;
        }
        
        if(iterator_idx == 0)
        {
            parsing_error("\"exec\": empty array.\n");
        }
         
        result->target_executable.argv[iterator_idx] = NULL;
        

        if( (real_path = realpath(result->target_executable.argv[0], NULL)) == NULL )
        {
            perror("realpath");
            fprintf(stderr, "File: %s\n", result->target_executable.argv[0]);
            exit(1);
        }
        
        free(result->target_executable.argv[0]);

        result->target_executable.argv[0] = real_path;
        result->target_executable.path = strdup(result->target_executable.argv[0]);

    }

    else
    {
        parsing_error("\"exec\" either missing or not [string, array].\n");
    }
    
    env = cJSON_GetObjectItemCaseSensitive(target, "env");
    
    if(!env)
    {
        result->target_executable.envp = NULL;
    }

    else if(cJSON_IsObject(env))
    {
        iterator_idx = 0;
        
        /* Enough space for all elements plus a NULL terminator */
        result->target_executable.envp = malloc( (cJSON_GetArraySize(env) + 1) * sizeof(char*) );
        
        cJSON_ArrayForEach(iterator, env)
        {
            /* Iterator is guaranteed to be a string */
            
            acc = cJSON_GetObjectItemCaseSensitive(env, iterator->string);
            
            if(!cJSON_IsString(acc))
            {
                parsing_error("\"env\": element `%lu` not [string].\n", iterator_idx);
            }
            
            /* env vars are passed to program as single char* like:
             * "KEY=VALUE"
             * We'll paste the two together with a '=' */
            
            size_t key_length   = strlen(iterator->string), 
                   value_length = strlen(acc->valuestring);
            
            /* Sanity check */
            if(strstr(iterator->string, "="))
                parsing_error("\"env\": key contains '='.\n");
        
            /* key length + length of '=' (1) + value length + length of '\0' (1) */
            result->target_executable.envp[iterator_idx] = malloc(key_length + value_length + 2);

            strcpy(result->target_executable.envp[iterator_idx], iterator->string);
            result->target_executable.envp[iterator_idx][key_length] = '=';
            strcpy(&result->target_executable.envp[iterator_idx][key_length + 1], acc->valuestring);
            
            iterator_idx++;
        }
        
        result->target_executable.envp[iterator_idx] = NULL;
    }

    else
    {
        parsing_error("\"env\": not [object]\n");
    }
    

    acc = cJSON_GetObjectItemCaseSensitive(parsed, "to_inject");

    if(!cJSON_IsString(acc))
    {
        parsing_error("\"to_inject\": either missing or not [string]\n");
    }
    
    if( (result->to_inject_path = realpath(acc->valuestring, NULL)) == NULL)
    {
        perror("realpath");
        fprintf(stderr, "File: %s\n", acc->valuestring);
        exit(1);
    }
    
    acc = cJSON_GetObjectItemCaseSensitive(parsed, "hooks");

    if(!acc)
    {
        result->hooks = NULL;
    }

    else if(cJSON_IsArray(acc))
    {

        hook_target_t *hook;
        result->hooks = NULL;
        iterator_idx = 0;

        cJSON_ArrayForEach(iterator, acc)
        {
            size_t offset_value;
            cJSON* mode;

            if(!cJSON_IsObject(iterator))
            {
                parsing_error("\"hooks\": element `%lu` not [object].\n", iterator_idx);
            }

            hook = calloc(1, sizeof *result->hooks);
            
            
            if( (mode = cJSON_GetObjectItemCaseSensitive(iterator, "mode")) == NULL)
            {
                /* Default to a detour hook. 
                 * Detour hooks should work in every scenario, 
                 * whilst replace hooks only works before a stack frame is set up. */
                hook->mode = HOOK_DETOUR;
            }
            else
            {
                if(cJSON_IsString(mode))
                {
                    if(!strcasecmp(mode->valuestring, "replace"))
                        hook->mode = HOOK_REPLACE;
                    else if(!strcasecmp(mode->valuestring, "detour"))
                        hook->mode = HOOK_DETOUR;
                    else
                        parsing_error("\"hooks\": element `%lu`: \"mode\" should either be \"replace\" or \"detour\", got \"%s\".\n", iterator_idx, mode->valuestring);
                }

                else
                {
                    parsing_error("\"hooks\": element `%lu`: \"mode\" not [string].\n", iterator_idx);
                }
            }

            hook_entry = cJSON_GetObjectItemCaseSensitive(iterator, "target_offset");
            json_parse_generic_offset(&hook->target_offset, hook_entry, iterator_idx);

            hook_entry = cJSON_GetObjectItemCaseSensitive(iterator, "hook_offset");
            json_parse_generic_offset(&hook->hook_offset, hook_entry, iterator_idx);

            hook->next = result->hooks;
            result->hooks = hook;
            iterator_idx++;

            #undef json_parse_generic_offset
        }
    }

    else
    {
        parsing_error("\"hooks\": not [array].\n")
    }

    cJSON_Delete(parsed);

    return result;

    #undef parse_error
}


void free_opts(opts_t* opts)
{
    free(opts->target_executable.path);
    
    #define maybe_free_string_array(array) \
        do { \
        if( (array) ) \
            while( *(array) ) free( *(array++)); \
        free(array); \
        array = NULL; } while(0);
                    
    maybe_free_string_array(opts->target_executable.argv);
    maybe_free_string_array(opts->target_executable.envp);

    #undef maybe_free_string_array
    
    free(opts->to_inject_path);
    

    hook_target_t *current = opts->hooks, *next;
    while(current)
    {
        next = current->next;
        free(current);
        current = next;
    }
}


static void print_generic_offset(generic_offset_t *offset)
{
    printf(TERM_COLOR_YELLOW);
    switch(offset->type)
    {
        case OFFSET_RAW:
            printf("0x%.8lx", offset->raw);
            break;
        case OFFSET_SYMBOL:
            printf("%s", offset->symbol);
            break;
        default:
            printf("<NONE>");
            break;
    }
    printf(TERM_RESET);
}

static void print_hook_target(hook_target_t *hook, char* target_file, char* lib_file)
{
    printf( TERM_COLOR_GREEN "%s" TERM_RESET "+", target_file);
    print_generic_offset(&hook->target_offset);
    printf(" -------> ");
    printf( TERM_COLOR_GREEN "%s" TERM_RESET "+", lib_file);
    print_generic_offset(&hook->hook_offset);

    printf(TERM_STYLE_BOLD " (mode: " TERM_COLOR_MAGENTA);
    
    if(hook->mode == HOOK_REPLACE)
        printf("REPLACE");
    else if(hook->mode == HOOK_DETOUR)
        printf("DETOUR");

    printf(")" TERM_RESET);
    putchar('\n');
}

void print_opts(opts_t *opts)
{
    size_t i;
    hook_target_t *hook;

    puts(TERM_STYLE_BOLD "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>" TERM_RESET);

    printf(TERM_STYLE_BOLD TERM_COLOR_MAGENTA "target path:  " TERM_RESET TERM_STYLE_DIM TERM_STYLE_UNDERLINE "\"%s\"" TERM_RESET "\n", opts->target_executable.path);
    puts(TERM_STYLE_BOLD TERM_COLOR_MAGENTA "argv:" TERM_RESET);
    
    i = 0;
    if(opts->target_executable.argv)
        while(opts->target_executable.argv[i])
            printf("\t\"" TERM_STYLE_DIM "%s" TERM_RESET "\"\n", opts->target_executable.argv[i++]);
   
    puts( TERM_STYLE_BOLD TERM_COLOR_MAGENTA "envp:" TERM_RESET);
    i = 0;

    if(opts->target_executable.envp)
        while(opts->target_executable.envp[i])
            printf("\t\"" TERM_STYLE_DIM "%s" TERM_RESET "\"\n", opts->target_executable.envp[i++]);
    
    putchar('\n');

    printf(TERM_STYLE_BOLD TERM_COLOR_MAGENTA "lib to inject: " TERM_RESET TERM_STYLE_DIM TERM_STYLE_UNDERLINE "\"%s\"" TERM_RESET "\n", opts->to_inject_path ? opts->to_inject_path : "NONE");
    
    hook = opts->hooks;
    
    if(hook)
        puts(TERM_STYLE_BOLD TERM_COLOR_MAGENTA "hooks:" TERM_RESET);

    while(hook)
    {
        putchar('\t');
        print_hook_target(hook, basename(opts->target_executable.path), basename(opts->to_inject_path) );
        hook = hook->next;
    }

    puts(TERM_STYLE_BOLD "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>" TERM_RESET);
}

generic_offset_t* resolve_generic_offset(generic_offset_t* offset, const func_symbol_t* symbol)
{
    switch(offset->type)
    {
        /* We need no changing */
        case OFFSET_RAW:
            return offset;
            break;

        case OFFSET_SYMBOL:
            while(symbol)
            {
                if(!strcmp(offset->symbol, symbol->identifier))
                {
                    offset->type = OFFSET_RAW;
                    offset->raw  = symbol->value;
                    return offset;
                }
                symbol = symbol->next;
            }
            return NULL;
            break;

        default:
            return NULL; 
    }
}

bool resolve_hook_targets(hook_target_t* hook_target, const elf_file_t* target_elf, const elf_file_t* lib_elf)
{
    /* Resolve hook target symbols. 
     * This will change every generic_offset_t into a OFFSET_RAW.
     * */
    bool success;
    success = true;
      
    while(hook_target)
    {
        
        if(hook_target->target_offset.type == OFFSET_SYMBOL && !resolve_generic_offset(&hook_target->target_offset, target_elf->info->func_symbols))
        {
            success = false;
            fprintf(stderr, "%s: Could not resolve symbol <%s>\n", target_elf->path, hook_target->target_offset.symbol);
        }

        if(hook_target->hook_offset.type == OFFSET_SYMBOL && !resolve_generic_offset(&hook_target->hook_offset, lib_elf->info->func_symbols))
        {
            success = false;
            fprintf(stderr, "%s: Could not resolve symbol <%s>\n", lib_elf->path, hook_target->hook_offset.symbol);
        }
        hook_target = hook_target->next;
    }
    
    return success;
}
