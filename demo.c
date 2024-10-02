#include "malloc.h"

#include <stdio.h>

static char heap_memory[1<<20];

// No attempt is made to simulate realistic memory allocation patterns,
// or testing the allocator thoroughly.
int
main() {
    malloc_init(heap_memory, sizeof(heap_memory));

    void* a = malloc(10);
    void* b = malloc(20);
    void* c = malloc(30);

    printf("a, b, c = [%p %p %p]\n", a, b, c);

    free(b);
    b = NULL;

    void* d = malloc(30);
    void* e = malloc(20);
    printf("d, e    = [%p %p]\n", d, e);
}
