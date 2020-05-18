FILES="`find ./ -type f -name '*.c'`"

gcc $FILES -g -Wall -Werror -lelf -o ./phook
