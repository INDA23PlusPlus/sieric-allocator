#include <stdio.h>

#include "free_list.h"

struct allocator {
    void *(*alloc)(size_t, size_t);
    void (*free)(void *);
    void *(*realloc)(void *, size_t);
} allocators[] = {
    {free_list_alloc, free_list_free, free_list_realloc},
};

#define NALLOCATORS (sizeof allocators / sizeof *allocators)

int main(void) {
    unsigned n;
retry:
    puts("Choose an allocator to test:\n0. free_list\n1. whatever");
    if(scanf("%u", &n) != 1 || n >= NALLOCATORS) {
        puts("Try again!");
        goto retry;
    }

    struct allocator *a = &allocators[n];
    printf("alloc:%p\nfree:%p\nrealloc:%p\n", a->alloc, a->free, a->realloc);
    
    return 0;
}
