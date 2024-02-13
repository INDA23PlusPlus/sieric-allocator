#include <stddef.h>
#include <stdint.h>

void  free_list_init(void);
void  free_list_fini(void);
void *free_list_alloc(size_t, uint8_t);
void  free_list_free(void *);
void *free_list_realloc(void *, size_t);
void  free_list_dump(void);
