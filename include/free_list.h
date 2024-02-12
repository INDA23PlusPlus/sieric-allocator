#include <stddef.h>

void *free_list_alloc(size_t, size_t);
void free_list_free(void *);
void *free_list_realloc(void *, size_t);
