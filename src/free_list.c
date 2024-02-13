#include "free_list.h"
#include "ordered_array.h"
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/**
 * stolen from myself 9 months ago:
 * https://gitlab.com/Simsva/shitos/-/blob/29da1aee365a860c1a3152a12e1a00e168f93b28/src/kernel/mem/heap.c
 */

#define HEAP_MAGIC    0x0defbeef
#define HEAP_INDEX_SZ 0x1000
#define HEAP_SZ       0x100000

typedef struct heap_header {
    uint32_t magic;
    uint8_t align; /* align on 1<<align boundaries */
    uint8_t hole;
    size_t size;
} heap_header_t;

typedef struct heap_footer {
    uint32_t magic;
    heap_header_t *hdr;
} heap_footer_t;

typedef struct heap {
    ord_arr_t index;
    void *start, *end, *max;
} heap_t;

static void heap_create(heap_t *heap, void *start, void *end, void *max, size_t index_sz);
/* static void heap_expand(heap_t *heap, size_t new_sz); */
static int header_compar(ord_arr_type_t a, ord_arr_type_t b);
/* static size_t heap_contract(heap_t *heap, size_t new_sz); */
static size_t heap_hole_find(heap_t *heap, size_t sz, uint8_t align);

static void *heap_alloc(heap_t *heap, size_t size, uint8_t align);
static void *heap_realloc(heap_t *heap, void *old, size_t size);
static void  heap_free(heap_t *heap, void *p);

size_t PAGE_SIZE;
heap_t heap = {0};

/* heap */
static int header_compar(ord_arr_type_t a, ord_arr_type_t b) {
    return ((heap_header_t *)a)->size < ((heap_header_t *)b)->size;
}

static void heap_create(heap_t *heap, void *start, void *end, void *max, size_t index_sz) {
    /* PAGE_SIZE = getpagesize(); */
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    /* vmem_heap_t *heap = (vmem_heap_t *)kmalloc(sizeof(vmem_heap_t)); */

    assert((uintptr_t)start % PAGE_SIZE == 0);
    assert((uintptr_t)end % PAGE_SIZE == 0);

    ord_arr_place(&heap->index, start, index_sz, &header_compar);
    start += sizeof(ord_arr_type_t) * index_sz;

    /* align start */
    start = (void *)((uintptr_t)(start + PAGE_SIZE-1) & ~(PAGE_SIZE-1));

    heap->start = start;
    heap->end = end;
    /* this isn't really necessary because the heap cannot expand */
    heap->max = max;

    /* create one large hole */
    heap_header_t *hole = (heap_header_t *)start;
    hole->size = end - start;
    hole->magic = HEAP_MAGIC;
    hole->align = 0;
    hole->hole = 1;

    heap_footer_t *ftr = end - sizeof(heap_footer_t);
    ftr->magic = HEAP_MAGIC;
    ftr->hdr = hole;

    ord_arr_insert(&heap->index, hole);
}

/* idk how this would even work using mmap(2) */
/* static void heap_expand(heap_t *heap, size_t new_sz) { */
/*     /\* align and check new_sz *\/ */
/*     new_sz = (new_sz + PAGE_SIZE-1) & ~(PAGE_SIZE-1); */
/*     assert(new_sz > (size_t)(heap->end - heap->start)); */
/*     assert(heap->start + new_sz <= heap->max); */

/*     unsigned get_flags = VMEM_GET_CREATE, alloc_flags = VMEM_FLAG_WRITE; */
/*     if(heap->kernel) get_flags |= VMEM_GET_KERNEL, alloc_flags |= VMEM_FLAG_KERNEL; */

/*     for(size_t old_sz = heap->end - heap->start; old_sz < new_sz; old_sz += PAGE_SIZE) */
/*         vmem_frame_alloc(vmem_get_page((uintptr_t)heap->start+old_sz, */
/*                                        get_flags), alloc_flags); */
/*     heap->end = heap->start + new_sz; */
/* } */

/* refer to heap_expand */
/* static size_t heap_contract(heap_t *heap, size_t new_sz) { */
/*     new_sz = (new_sz + PAGE_SIZE-1) & ~(PAGE_SIZE-1); */
/*     if(new_sz < HEAP_INITIAL_SZ) new_sz = HEAP_INITIAL_SZ; */
/*     assert(new_sz < (size_t)(heap->end - heap->start)); */

/*     size_t old_sz = heap->end - heap->start; */
/*     while(old_sz > new_sz) { */
/*         vmem_frame_free(vmem_get_page((uintptr_t)heap->start+old_sz, */
/*                                       VMEM_GET_CREATE|VMEM_GET_KERNEL)); */
/*         old_sz -= PAGE_SIZE; */
/*     } */
/*     heap->end = heap->start + new_sz; */
/*     return new_sz; */
/* } */

static size_t heap_hole_find(heap_t *heap, size_t size, uint8_t align) {
    for(size_t iter = 0; iter < heap->index.size; iter++) {
        heap_header_t *header;
        size_t hole_sz;

        header = (heap_header_t *)ord_arr_get(&heap->index, iter);
        hole_sz = header->size;

        if(align) {
            uintptr_t loc;
            size_t off;

            /* align location AFTER the header */
            loc = (uintptr_t)header + sizeof(heap_header_t);
            off = 0;
            if(loc & ((1<<align)-1))
                off = (1<<align) - (loc & ((1<<align)-1));
            if(off < sizeof(heap_header_t)) off += 1<<align;
            if(off > hole_sz) continue;
            hole_sz -= off;
        }
        if(hole_sz >= size)
            return iter;
    }
    /* not found */
    return SIZE_MAX;
}

static void *heap_alloc(heap_t *heap, size_t size, uint8_t align) {
    size_t real_size, hole_size, hole;
    heap_header_t *orig_header;

    /* sweep the bugs under the rug */
    if(align && align < 6) align = 6;

    real_size = size + sizeof(heap_header_t) + sizeof(heap_footer_t);
    hole = heap_hole_find(heap, real_size, align);

    if(hole == SIZE_MAX) {
        assert(false && "Heap cannot expand lol");
        /* size_t heap_newsz, heap_oldsz = heap->end - heap->start; */
        /* void *heap_oldend = heap->end; */

        /* vmem_heap_expand(heap, heap_oldsz + real_size); */
        /* heap_newsz = heap->end - heap->start; */

        /* size_t idx = SIZE_MAX; */
        /* void *cur_max = NULL; */
        /* for(size_t i = 0; i < heap->index.size; i++) { */
        /*     void *tmp = ord_arr_get(&heap->index, i); */
        /*     if(tmp > cur_max) { */
        /*         cur_max = tmp; */
        /*         idx = i; */
        /*     } */
        /* } */

        /* if(idx == SIZE_MAX) { */
        /*     heap_header_t *hdr = (heap_header_t *)heap_oldend; */
        /*     hdr->magic = HEAP_MAGIC; */
        /*     hdr->size = heap_newsz - heap_oldsz; */
        /*     hdr->hole = 1; */
        /*     hdr->align = 0; */

        /*     heap_footer_t *ftr = (heap_footer_t *)((void *)hdr + hdr->size - sizeof(heap_footer_t)); */
        /*     ftr->magic = HEAP_MAGIC; */
        /*     ftr->hdr = hdr; */

        /*     ord_arr_insert(&heap->index, hdr); */
        /* } else { */
        /*     heap_header_t *hdr = cur_max; */
        /*     hdr->magic = HEAP_MAGIC; */
        /*     hdr->size += heap_newsz - heap_oldsz; */

        /*     heap_footer_t *ftr = (heap_footer_t *)((void *)hdr + hdr->size - sizeof(heap_footer_t)); */
        /*     ftr->magic = HEAP_MAGIC; */
        /*     ftr->hdr = hdr; */
        /* } */

        /* return heap_alloc(heap, size, align); */
    }

    orig_header = ord_arr_get(&heap->index, hole);
    hole_size = orig_header->size;
    if(hole_size - real_size < sizeof(heap_header_t) + sizeof(heap_footer_t)) {
        real_size = hole_size;
    }

    /* align and create a hole before */
    if(align) {
        uintptr_t off = (1<<align) - ((uintptr_t)orig_header & ((1<<align)-1));
        /* make sure the header fits */
        if(off < sizeof(heap_header_t))
            off += 1<<align;

        void *new_loc = (void *)orig_header + off - sizeof(heap_header_t);

        orig_header->size = off - sizeof(heap_header_t);
        orig_header->magic = HEAP_MAGIC;
        orig_header->hole = 1;
        orig_header->align = 0;

        heap_footer_t *footer = new_loc - sizeof(heap_footer_t);
        footer->magic = HEAP_MAGIC;
        footer->hdr = orig_header;

        hole_size -= orig_header->size;
        orig_header = new_loc;
    } else {
        ord_arr_remove(&heap->index, hole);
    }

    orig_header->size = real_size;
    orig_header->magic = HEAP_MAGIC;
    orig_header->hole = 0;
    orig_header->align = align;
    heap_footer_t *footer = (void *)orig_header + real_size - sizeof(heap_footer_t);
    footer->magic = HEAP_MAGIC;
    footer->hdr = orig_header;

    if(hole_size - real_size > 0) {
        heap_header_t *header = (void *)orig_header + orig_header->size;
        header->size = hole_size - real_size;
        header->magic = HEAP_MAGIC;
        header->hole = 1;
        header->align = 0;

        heap_footer_t *footer = (void *)header + header->size - sizeof(heap_footer_t);
        if((uintptr_t)footer < (uintptr_t)heap->end) {
            footer->magic = HEAP_MAGIC;
            footer->hdr = header;
        }

        ord_arr_insert(&heap->index, header);
    }

    return (void *)orig_header + sizeof(heap_header_t);
}

static void *heap_realloc(heap_t *heap, void *old, size_t size) {
    if(!old) return heap_alloc(heap, size, 0);
    if(!size) { heap_free(heap, old); return NULL; }

    /* this is more useful in calculations */
    size += sizeof(heap_header_t) + sizeof(heap_footer_t);

    heap_header_t *hdr = old - sizeof(heap_header_t);
    heap_header_t *ftr = (void *)hdr + hdr->size - sizeof(heap_footer_t);
    heap_header_t *rhdr = (void *)ftr + sizeof(heap_footer_t);

    assert(hdr->magic == HEAP_MAGIC);
    assert(ftr->magic == HEAP_MAGIC);
    assert(hdr->hole == 0 && "realloc on freed segment");

    if(hdr->size == size) return old;

    /* shrink, new < old */
    if(hdr->size > size) {
        if((void *)rhdr + sizeof(heap_header_t) <= heap->end && rhdr->hole) {
            /* extend right hole */
            size_t i = ord_arr_index(&heap->index, rhdr);
            assert(i != SIZE_MAX && "Hole not in index");
            ord_arr_remove(&heap->index, i);

            heap_header_t *new_rhdr = (void *)hdr + size;
            new_rhdr->magic = HEAP_MAGIC;
            new_rhdr->align = 0;
            new_rhdr->size = rhdr->size + (size - hdr->size);
            new_rhdr->hole = 1;

            heap_footer_t *old_rftr = (void *)rhdr + rhdr->size - sizeof(heap_footer_t);
            old_rftr->hdr = new_rhdr;

            ord_arr_insert(&heap->index, new_rhdr);
        } else if(size - hdr->size >= sizeof(heap_header_t) + sizeof(heap_footer_t)) {
            /* shrink if a new hole will fit */
            heap_header_t *hole = (void *)hdr + size;
            hole->magic = HEAP_MAGIC;
            hole->hole = 1;
            hole->size = size - hdr->size;
            hole->align = 0;

            heap_footer_t *hole_ftr = (void *)hole + hole->size - sizeof(heap_footer_t);
            hole_ftr->magic = HEAP_MAGIC;
            hole_ftr->hdr = hole;

            ord_arr_insert(&heap->index, hole);
        } else {
            /* if a new hole won't fit, keep the old size */
            return old;
        }

        /* add new footer */
        hdr->size = size;
        heap_footer_t *new_ftr = (void *)hdr + hdr->size - sizeof(heap_footer_t);
        new_ftr->magic = HEAP_MAGIC;
        new_ftr->hdr = hdr;
        return old;
    }

    /* extend, new > old */
    if((void *)rhdr + sizeof(heap_header_t) > heap->end) {
        assert(false && "Heap cannot expand lol");
        /* /\* expand heap *\/ */
        /* size_t heap_oldsz = heap->end - heap->start; */
        /* vmem_heap_expand(heap, heap_oldsz + size); */

        /* hdr->size = size; */
        /* heap_footer_t *new_ftr = (void *)hdr + hdr->size - sizeof(heap_footer_t); */
        /* new_ftr->magic = HEAP_MAGIC; */
        /* new_ftr->hdr = hdr; */

        /* /\* after expansion we are guaranteed to fit a new hole *\/ */
        /* heap_header_t *hole = (void *)new_ftr + sizeof(heap_footer_t); */
        /* hole->magic = HEAP_MAGIC; */
        /* hole->hole = 1; */
        /* hole->size = (uintptr_t)heap->end - (uintptr_t)hole; */
        /* hole->align = 0; */

        /* heap_footer_t *hole_ftr = (void *)hole + hole->size - sizeof(heap_footer_t); */
        /* hole_ftr->magic = HEAP_MAGIC; */
        /* hole_ftr->hdr = hole; */

        /* ord_arr_insert(&heap->index, hole); */

        /* return old; */
    }

    if(rhdr->hole) {
        /* merge with right hole */
        heap_footer_t *rftr = (void *)rhdr + rhdr->size - sizeof(heap_footer_t);

        size_t extra_size = size - hdr->size;
        size_t i = ord_arr_index(&heap->index, rhdr);
        ord_arr_remove(&heap->index, i);
        if(rhdr->size < extra_size) {
            /* if new allocation is larger than the hole then
             * claim the hole and recurse */
            hdr->size += rhdr->size;
            rftr->hdr = hdr;

            return heap_realloc(heap, old, size);
        } else if(rhdr->size - extra_size >= sizeof(heap_header_t) + sizeof(heap_footer_t)) {
            /* a new hole fits */
            hdr->size = size;
            heap_footer_t *new_ftr = (void *)hdr + hdr->size - sizeof(heap_footer_t);
            new_ftr->magic = HEAP_MAGIC;
            new_ftr->hdr = hdr;

            heap_header_t *hole = (void *)new_ftr + sizeof(heap_footer_t);
            hole->magic = HEAP_MAGIC;
            hole->hole = 1;
            hole->size = (uintptr_t)rftr + sizeof(heap_footer_t) - (uintptr_t)hole;
            hole->align = 0;

            rftr->hdr = hole;

            ord_arr_insert(&heap->index, hole);
            return old;
        } else {
            /* no new hole fits, so claim the entire hole */
            hdr->size += rhdr->size;
            rftr->hdr = hdr;
            return old;
        }
    }

    /* no way to extend our allocation means we need a new one */
    void *new_alloc = heap_alloc(heap, size - sizeof(heap_header_t)
                                                 - sizeof(heap_footer_t),
                                      hdr->align);
    memcpy(new_alloc, old, hdr->size - sizeof(heap_header_t)
                                     - sizeof(heap_footer_t));
    heap_free(heap, old);
    return new_alloc;
}

static void heap_free(heap_t *heap, void *p) {
    if(p == NULL) return;

    heap_header_t *hdr = p - sizeof(heap_header_t);
    heap_footer_t *ftr = (void *)hdr + hdr->size - sizeof(heap_footer_t);

    assert(hdr->magic == HEAP_MAGIC);
    assert(ftr->magic == HEAP_MAGIC);
    assert(hdr->hole == 0 && "Double free");

    hdr->hole = 1;
    hdr->align = 0;
    bool add_hole = true;

    /* unify left */
    heap_footer_t *lftr = (void *)hdr - sizeof(heap_footer_t);
    if(lftr->magic == HEAP_MAGIC && lftr->hdr->hole) {
        lftr->hdr->size += hdr->size;
        hdr = lftr->hdr;
        ftr->hdr = hdr;
        add_hole = false; /* already in index */
    }

    /* unify right */
    heap_header_t *rhdr = (void *)ftr + sizeof(heap_footer_t);
    if(rhdr->magic == HEAP_MAGIC && rhdr->hole) {
        hdr->size += rhdr->size;
        ftr = (void *)rhdr + rhdr->size - sizeof(heap_footer_t);
        ftr->hdr = hdr;

        size_t idx = 0;
        while(idx < heap->index.size && ord_arr_get(&heap->index, idx) != rhdr)
            idx++;

        /* make sure it actually exists */
        assert(idx < heap->index.size);
        ord_arr_remove(&heap->index, idx);
    }

    if(add_hole) ord_arr_insert(&heap->index, hdr);
}

/* dump information about heap segments */
static void heap_dump(heap_t *heap) {
    heap_header_t *hdr = heap->start;

    while((void *)hdr < heap->end) {
        if(hdr->magic != HEAP_MAGIC) goto magic_err;
        heap_footer_t *ftr = (void *)hdr + hdr->size - sizeof(heap_footer_t);
        if(ftr->magic != HEAP_MAGIC) goto magic_err;
        printf("%p\talloc:%d sz:%#zx\trsz:%#zx\n",
               hdr, !hdr->hole,
               hdr->size - sizeof(heap_header_t) - sizeof(heap_footer_t),
               hdr->size);
        hdr = (void *)hdr + hdr->size;
    }
    return;

magic_err:
    printf("\033[41mSegment at %p not intact!\033[m\n", hdr);
}

/* actual interface */
void free_list_init(void) {
    void *start = mmap(NULL, HEAP_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    heap_create(&heap, start, start+HEAP_SZ, start+HEAP_SZ, HEAP_INDEX_SZ);
}

void free_list_fini(void) {
    return;
}

/** alloc sz bytes aligned at 1<<align boundaries */
void *free_list_alloc(size_t sz, uint8_t align) {
    return heap_alloc(&heap, sz, align);
}

void free_list_free(void *p) {
    heap_free(&heap, p);
}

void *free_list_realloc(void *p, size_t sz) {
    return heap_realloc(&heap, p, sz);
}

void free_list_dump(void) {
    heap_dump(&heap);
}
