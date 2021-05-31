mkdir -p build
gcc -Wall -Werror ./target.c -o build/target_dynamic -no-pie
gcc -Wall -Werror ./target.c -o build/target_static -static

gcc -Wall -Werror  ./library.c -o build/inject.o -fpic -c
gcc -shared -o build/inject.so build/inject.o
