FILES="`find ./ -type f -name '*.c'`"

gcc $FILES -o ./phook -g -Wall -Werror
