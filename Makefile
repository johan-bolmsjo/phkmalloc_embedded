CFLAGS := -Wall -Wextra -pedantic -std=c11 -g -O0

demo: demo.o malloc.o

.PHONY: clean
clean:
	rm -f demo *.o
