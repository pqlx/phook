#include <stdio.h>
#include <stdlib.h>

void target(void)
{
    printf("`target` called.\n");
}

int main(void)
{
    puts("Starting test...");

    for(int i = 0; i < 10; ++i)
    {
        target();
    }

    puts("Ending test...");
}
