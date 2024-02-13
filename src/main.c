#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "free_list.h"

struct allocator {
    void (*init)(void);
    void (*fini)(void);
    void *(*alloc)(size_t, uint8_t);
    void (*free)(void *);
    void *(*realloc)(void *, size_t);
    void (*debug)(void);
} allocators[] = {
    {free_list_init, free_list_fini, free_list_alloc,
     free_list_free, free_list_realloc, free_list_dump},
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
    puts("-------- init --------");
    a->init();
    a->debug();
    puts("-------- alloc --------");
    /* weird alignments cause segfaults or corrupt headers */
    char *str = a->alloc(32, 2);
    strcpy(str, "Tjena mors");
    printf("str: %p (%s)\n", str, str);
    assert(((uintptr_t)str & ((1<<0)-1)) == 0 && "alignment");
    a->debug();
    puts("-------- free --------");
    a->free(str);
    a->debug();
    puts("-------- fini --------");
    a->fini();

    return 0;
}
