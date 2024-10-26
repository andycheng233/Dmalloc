#include "dmalloc.hh"
#include <cstdio>
#include <cassert>
#include <cstring>
// A correct execution should not report errors.

int main()
{
    for (int i = 0; i != 10; ++i)
    {
        // printf("----- %d -----\n", i); !!!!!!!!!!!!!!!!!!!!
        int *ptr = (int *)malloc(10 * sizeof(int));
        ptr[i] = i;
        for (int j = 0; j != 10; ++j)
        {
            // printf("\tTHe pointer is editing address: %d\n", (uintptr_t)ptr); !!!!!!!!!!!!!!!!!!!
            ptr[i] = i;
        }
        free(ptr);
    }
    dmalloc_print_statistics();
}

//! alloc count: active          0   total         10   fail          0
//! alloc size:  active          0   total        400   fail          0
