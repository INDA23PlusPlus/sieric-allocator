#ifndef ORDERED_ARRAY_H_
#define ORDERED_ARRAY_H_

#include <stddef.h>

typedef void *ord_arr_type_t;

typedef struct ord_arr {
    ord_arr_type_t *array;
    size_t size, max_size;
    int (*compar)(ord_arr_type_t, ord_arr_type_t);
} ord_arr_t;

int ord_arr_stdcompar(ord_arr_type_t a, ord_arr_type_t b);

void ord_arr_place(ord_arr_t *out, void *addr, size_t max_size,
                   int (*compar)(ord_arr_type_t, ord_arr_type_t));

void ord_arr_insert(ord_arr_t *array, ord_arr_type_t el);
ord_arr_type_t ord_arr_get(ord_arr_t *array, size_t i);
size_t ord_arr_index(ord_arr_t *array, ord_arr_type_t el);
void ord_arr_remove(ord_arr_t *array, size_t i);

#endif /* ORDERED_ARRAY_H_ */
