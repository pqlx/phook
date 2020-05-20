#include <stdio.h>
#include <stdlib.h>

void target(void)
{
    printf("Hook failed!\n");
}

int main(void)
{
    puts("Starting test...");

    puts("If you see 'Hook failed!' appear, the hook has failed");
    puts("If you see 'Hit hook!' appear, the hook has succeeded");
    for(int i = 0; i < 10; ++i)
    {
        target();
    }

    puts("Ending test...");
}
