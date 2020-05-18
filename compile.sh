FILES="`find ./src -type f -name '*.c'`"

gcc $FILES -g -Wall -Werror -lelf -o ./phook
