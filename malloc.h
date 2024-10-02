/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <dev@johan.bitmaster.se> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Johan Bolmsjö
 * ----------------------------------------------------------------------------
 */
#pragma once

#include <stddef.h> /* For size_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the global heap to use the specified memory region.
 * Must be called before any other malloc related function.
 */
void malloc_init(void* base, size_t size);

/* Standard malloc functions */

void* malloc(size_t size);
void* calloc(size_t nmemb, size_t size);
void* realloc(void *ptr, size_t size);
void  free(void *ptr);

#ifdef __cplusplus
}
#endif
