#include "free_list.h"

void *free_list_alloc(size_t sz, size_t align) {
    return NULL;
}

void free_list_free(void *p) {
}

void *free_list_realloc(void *p, size_t sz) {
    return p;
}
