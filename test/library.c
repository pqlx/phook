#include <stdio.h>

int hook(void)
{
    puts("`hook` called.");
    return 1;
}
