/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <dev@johan.bitmaster.se> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Johan Bolmsjö
 * ----------------------------------------------------------------------------
 */
#pragma once

/*
 * This whole file contain settings that may need to be configured for a target
 * platform depending on available features.
 */

/*
 * Types used by malloc.
 */
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;

/*
 * Defining EXTRA_SANITY will enable extra checks which are related
 * to internal conditions and consistency in malloc.c. This has a
 * noticeable runtime performance hit, and generally will not do you
 * any good unless you fiddle with the internals of malloc or want
 * to catch random pointer corruption as early as possible.
 */
#if 0
#define EXTRA_SANITY
#endif

/*
 * What to use for Junk.  This is the byte value we use to fill with
 * when the 'J' option is enabled.
 */
#define SOME_JUNK	0xd0		/* as in "Duh" :-) */

/*
 * The basic parameters you can tweak.
 *
 * malloc_pageshift	pagesize = 1 << malloc_pageshift
 *			It's probably best if this is the native
 *			page size, but it doesn't have to be.
 *
 * malloc_minsize	minimum size of an allocation in bytes.
 *			If this is too small it's too much work
 *			to manage them.  This is also the smallest
 *			unit of alignment used for the storage
 *			returned by malloc/realloc.
 *
 */
#define malloc_pageshift 12U
#define malloc_minsize	 16U

#include <string.h> /* For memcpy, memset, strlen */
#include <stdlib.h> /* For abort  */
#include <stddef.h> /* For size_t */
#include <unistd.h> /* For write  */

/* memcpy function to be used by malloc. */
#define malloc_config__memcpy memcpy

/* memset function to be used by malloc. */
#define malloc_config__memset memset

/* strlen function to be used by malloc (for diagnostics). */
#define malloc_config__strlen strlen

/* Function to call when malloc terminates because of heap inconsistencies. */
#define malloc_config__abort abort

/*
 * Prefix to be used for diagnostic from malloc related functions
 */
#define mallloc_config__diag_prefix "myprog: "

static __inline__ void
posix_diag_writer(const void* buf, size_t count)
{
    int r = write(2 /* stderr */, buf, count);
    (void)r;
}

/*
 * Function to be called to output diagnostic messages.
 */
#define malloc_config__diag_writer posix_diag_writer

/*
 * Functions to lock and unlock the heap in a preemptive thread environment.
 * Please note that this malloc is a poor choice for threaded applications, especially in a multi-processor context.
 *
 * These functions (if defined) must not allocate memory using malloc.
 */
#define malloc_config__thread_lock()
#define malloc_config__thread_unlock()

/*
 * Malloc options specified as a string of characters with the following meaning.
 *
 *   '>' Double page cache (may be specified multiple times)
 *   '<' Half page cache (may be specified multiple times)
 *
 * On/Off features where upper case means on and lower case off:
 *
 *   'A' Abort on non fatal errors instead of returning an error value.
 *   'R' Realloc by malloc + copy.
 *   'J' Fill freed memory with junk character specified in malloc_config.h (implies 'R').
 *   'V' Allocating zero bytes returns 0.
 *   'X' Write out of memory diagnostic messages.
 *   'Z' Zero allocated memory (implies 'J').
 */
static const char* malloc_options = "AZ";
