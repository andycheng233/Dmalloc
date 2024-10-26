#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <unordered_map>
#include <string>

using namespace std;

#define CANARY_SIZE 64
#define CANARY_MEMORY (CANARY_SIZE * sizeof(long))
#define CANARY_CODE 0xDEADBEEF
#define MALLOC_CODE 0xABCDABCD

struct header
{
    size_t size;
    const char *file;
    long line;
    bool isFreed;
    long mallocCode;
    struct header *next;
};

struct heavyInfo
{
    size_t size;
    const char *file;
    long line;
};

std::unordered_map<void *, unsigned int> base_allocated_map;
std::unordered_map<string, heavyInfo *> heavy_hitters_map;

unsigned long long nactive = 0;     // # active allocations
unsigned long long active_size = 0; // # bytes in active allocations
unsigned long long ntotal = 0;      // # total allocations
unsigned long long total_size = 0;  // # bytes in total allocations
unsigned long long nfail = 0;       // # failed allocation attempts
unsigned long long fail_size = 0;   // # bytes in failed alloc attempts
uintptr_t heap_min = 0;             // smallest allocated addr
uintptr_t heap_max = 0;             // largest allocated addr

/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void *dmalloc_malloc(size_t sz, const char *file, long line)
{
    if (sz == 0)
        return base_malloc(0);

    if (sz > SIZE_MAX - 1000)
    {
        nfail++;
        fail_size += sz;
        return nullptr;
    }

    size_t offset = sizeof(header) % 16;

    header *h = (header *)base_malloc(sizeof(header) + offset + CANARY_MEMORY + sz + CANARY_MEMORY);

    h->size = sz;
    h->file = file;
    h->line = line;
    h->isFreed = false;
    h->mallocCode = MALLOC_CODE;
    h->next = NULL;

    base_allocated_map.insert(std::make_pair(h, h->size));

    long *uCanary = (long *)((uintptr_t)h + sizeof(header) + offset);
    long *oCanary = (long *)((uintptr_t)h + sizeof(header) + offset + CANARY_MEMORY + sz);

    for (size_t i = 0; i < CANARY_SIZE; i++)
    {
        uCanary[i] = CANARY_CODE;
        oCanary[i] = CANARY_CODE;
    }

    nactive++;
    active_size += sz;
    ntotal++;
    total_size += sz;

    uintptr_t p = (uintptr_t)h + sizeof(header) + offset + CANARY_MEMORY;

    if (heap_min == 0 && heap_max == 0)
    {
        heap_min = p;
        heap_max = p + sz;
    }

    else
    {
        if (p < heap_min)
            heap_min = p;
        if (p + sz > heap_max)
            heap_max = p + sz;
    }

    string key = file + to_string(line);
    if (heavy_hitters_map.find(key) == heavy_hitters_map.end())
    {
        heavyInfo *newH = (heavyInfo *)base_malloc(sizeof(heavyInfo));
        newH->size = sz;
        newH->file = file;
        newH->line = line;
        heavy_hitters_map[key] = newH;
    }

    else
        heavy_hitters_map[key]->size += sz;

    return (void *)p;
}

/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void dmalloc_free(void *ptr, const char *file, long line)
{
    if (ptr == NULL)
        return;

    size_t offset = sizeof(header) % 16;

    header *h = (header *)((uintptr_t)ptr - CANARY_MEMORY - offset - sizeof(header));

    if (h == NULL)
    {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap", file, line, ptr);
        exit(1);
    }

    if (((uintptr_t)ptr > heap_max || (uintptr_t)ptr < heap_min))
    {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap", file, line, ptr);
        exit(1);
    }

    if (h->mallocCode != MALLOC_CODE)
    {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        for (auto pair : base_allocated_map)
        {
            header *h2 = (header *)pair.first;
            uintptr_t p = (uintptr_t)h2 + sizeof(header) + sizeof(header) % 16 + CANARY_MEMORY;
            if ((uintptr_t)ptr >= p && (uintptr_t)ptr <= p + h2->size)
            {
                uintptr_t bytes = (uintptr_t)ptr - p;
                fprintf(stderr, "  %s:%ld: %p is %zd bytes inside a %zu byte region allocated here", h2->file, h2->line, ptr, bytes, h2->size);
                exit(1);
            }
        }

        fprintf(stderr, "what?");
        exit(1);
    }

    if (h->isFreed)
    {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free", file, line, ptr);
        exit(1);
    }

    long *uCanary = (long *)((uintptr_t)h + sizeof(header) + offset);
    long *oCanary = (long *)((uintptr_t)h + sizeof(header) + offset + CANARY_MEMORY + h->size);

    for (size_t i = 0; i < CANARY_SIZE; i++)
    {
        if (oCanary[i] != CANARY_CODE || uCanary[i] != CANARY_CODE)
        {
            fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p", file, line, ptr);
            exit(1);
        }
    }

    nactive--;
    active_size -= h->size;

    h->isFreed = true;

    base_allocated_map.erase(h);

    return base_free(h);
}

/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void *dmalloc_calloc(size_t nmemb, size_t sz, const char *file, long line)
{
    if (nmemb != 0 && sz > SIZE_MAX / nmemb)
    {
        nfail++;
        fail_size += sz;
        return nullptr;
    }

    void *ptr = dmalloc_malloc(nmemb * sz, file, line);
    if (ptr)
    {
        memset(ptr, 0, nmemb * sz);
    }

    return ptr;
}

/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics *stats)
{
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_statistics));
    stats->nactive = nactive;
    stats->active_size = active_size;
    stats->ntotal = ntotal;
    stats->total_size = total_size;
    stats->nfail = nfail;
    stats->fail_size = fail_size;
    stats->heap_min = heap_min;
    stats->heap_max = heap_max;
}

/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics()
{
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void dmalloc_print_leak_report()
{
    for (auto pair : base_allocated_map)
    {
        header *h = (header *)pair.first;
        uintptr_t p = (uintptr_t)h + sizeof(header) + sizeof(header) % 16 + CANARY_MEMORY;
        fprintf(stdout, "LEAK CHECK: %s:%ld: allocated object %p with size %d\n", h->file, h->line, (void *)p, pair.second);
    }
}

/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report()
{
    size_t totalBytes = 0;
    heavyInfo printHeavy[5];

    for (size_t i = 0; i < 5; i++)
    {
        printHeavy[i].size = 0;
        printHeavy[i].file = NULL;
        printHeavy[i].line = 0;
    }

    for (auto pair : heavy_hitters_map)
    {
        heavyInfo *temp = pair.second;
        totalBytes += temp->size;

        for (size_t i = 0; i < 5; i++)
        {
            if (printHeavy[i].size < temp->size)
            {
                size_t storeSize = printHeavy[i].size;
                const char *storeFile = printHeavy[i].file;
                long storeLine = printHeavy[i].line;

                printHeavy[i].size = temp->size;
                printHeavy[i].file = temp->file;
                printHeavy[i].line = temp->line;

                temp->size = storeSize;
                temp->file = storeFile;
                temp->line = storeLine;
            }
        }

        base_free(temp);
    }

    for (size_t i = 0; i < 5; i++)
    {
        double percent = (double)printHeavy[i].size / totalBytes * 100;

        if (percent >= 20)
            fprintf(stdout, "HEAVY HITTER: %s:%ld: %zu bytes (~%.1f%%)\n", printHeavy[i].file, printHeavy[i].line, printHeavy[i].size, percent);
    }
}