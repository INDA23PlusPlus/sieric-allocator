#include "ordered_array.h"

#include <stdint.h>
#include <string.h>
#include <assert.h>

int ord_arr_stdcompar(ord_arr_type_t a, ord_arr_type_t b) {
    return a < b;
}

void ord_arr_place(ord_arr_t *out, void *addr, size_t max_size,
                        int (*compar)(ord_arr_type_t, ord_arr_type_t)) {
    out->array = addr;
    memset(out->array, 0, max_size * sizeof(ord_arr_type_t));
    out->size = 0;
    out->max_size = max_size;
    out->compar = compar;
}

void ord_arr_insert(ord_arr_t *array, ord_arr_type_t el) {
    assert(array->compar);

    uint32_t i = 0;
    while(i < array->size && array->compar(array->array[i], el)) i++;
    if(i == array->size)
        /* will extend over max_size */
        array->array[array->size++] = el;
    else {
        memmove(array->array + i+1, array->array + i,
                (array->size - i) * sizeof(ord_arr_type_t));
        array->array[i] = el;
        array->size++;
    }
}

ord_arr_type_t ord_arr_get(ord_arr_t *array, size_t i) {
    assert(i < array->size);
    return array->array[i];
}

size_t ord_arr_index(ord_arr_t *array, ord_arr_type_t el) {
    for(size_t i = 0; i < array->size; i++)
        if(array->array[i] == el) return i;
    return SIZE_MAX;
}

void ord_arr_remove(ord_arr_t *array, size_t i) {
    assert(i < array->size);
    array->size--;
    memmove(array->array + i, array->array + i+1,
            (array->size - i) * sizeof(ord_arr_type_t));
}
