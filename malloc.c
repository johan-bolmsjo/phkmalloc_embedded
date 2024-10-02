/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.ORG> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD$
 *
 */

#include "malloc.h"
#include "malloc_config.h"

/* To prevent porting mistakes */
#define mmap   "no_mmap"
#define munmap "no_munmap"
#define brk    "no_brk"
#define sbrk   "no_sbrk"

/*
 * This structure describes a page worth of chunks.
 */

struct pginfo {
    struct pginfo	*next;	/* next on the free list */
    void		*page;	/* Pointer to the page */
    u_short		size;	/* size of this page's chunks */
    u_short		shift;	/* How far to shift for this size chunks */
    u_short		free;	/* How many free chunks */
    u_short		total;	/* How many chunk */
    u_int		bits[1]; /* Which chunks are free */
};

/*
 * This structure describes a number of free pages.
 */

struct pgfree {
    struct pgfree	*next;	/* next run of free pages */
    struct pgfree	*prev;	/* prev run of free pages */
    void		*page;	/* pointer to free pages */
    void		*end;	/* pointer to end of free pages */
    size_t		size;	/* number of bytes free */
};

/*
 * How many bits per u_int in the bitmap.
 * Change only if not 8 bits/byte
 */
#define	MALLOC_BITS	(8*sizeof(u_int))

/*
 * Magic values to put in the page_directory
 */
#define MALLOC_NOT_MINE	((struct pginfo*) 0)
#define MALLOC_FREE 	((struct pginfo*) 1)
#define MALLOC_FIRST	((struct pginfo*) 2)
#define MALLOC_FOLLOW	((struct pginfo*) 3)
#define MALLOC_MAGIC	((struct pginfo*) 4)

#define malloc_pagesize			(1UL<<malloc_pageshift)

/* Threshold for allocating whole pages */
#define malloc_maxsize			((malloc_pagesize)>>1)

/* A mask for the offset inside a page.  */
#define malloc_pagemask	((malloc_pagesize)-1)

#define pageround(foo)  (((foo) + (malloc_pagemask)) & (~(malloc_pagemask)))
#define pgdirround(foo) (((foo) + (7)) & (~(7))) /* Assume 8 byte pointers is worst case */
#define ptr2index(foo)  (((u_long)(foo) >> malloc_pageshift) - malloc_origo)

/* Set when initialization has been done */
static unsigned malloc_started;

/* Recusion flag for public interface. */
static int malloc_active;

/* Number of free pages we cache */
static unsigned malloc_cache = 16;

/* The offset from pagenumber to index into the page directory */
static u_long malloc_origo;

/* The last index in the page directory we care about */
static u_long last_index;

/* my last break. */
static void *last_brk;

/* Pointer to page directory. */
static struct pginfo **page_dir;

/* How many slots in the page directory */
static unsigned	malloc_ninfo;

/* Free pages line up here */
static struct pgfree free_list;

/* Abort(), user doesn't handle problems.  */
static int malloc_abort;

/* Are we trying to die ?  */
static int suicide;

/* always realloc ?  */
static int malloc_realloc;

/* xmalloc behaviour ?  */
static int malloc_xmalloc;

/* sysv behaviour for malloc(0) ?  */
static int malloc_sysv;

/* zero fill ?  */
static int malloc_zero;

/* junk fill ?  */
static int malloc_junk;

/* one location cache for free-list holders */
static struct pgfree *px;

/* Name of the current public function */
static const char *malloc_func;

/* Bounds given to malloc_init */
static void* malloc_heap_start;
static void* malloc_heap_end;

/* Emulated break address. Since phkmalloc was written for a Unix environment
 * it's easiest to just emulate these APIs. */
static void* malloc_heap_brk;

/*
 * Necessary function declarations
 */
static void *imalloc(size_t size);
static void ifree(void *ptr);
static void *irealloc(void *ptr, size_t size);

/* Emulation of Unix brk system function */
static int
emu_brk(void* addr)
{
    if (addr < malloc_heap_start || addr > malloc_heap_end)
        return -1; /* ENOMEM */

    malloc_heap_brk = addr;
    return 0;
}

/* Emulation of Unix sbrk system function */
static void*
emu_sbrk(long increment)
{
    void* const old_brk = malloc_heap_brk;
    void* const new_brk = (char*)malloc_heap_brk + increment;

    if (new_brk < malloc_heap_start || new_brk > malloc_heap_end)
        return (void*)(long)-1; /* ENOMEM */

    malloc_heap_brk = new_brk;
    return old_brk;
}

static void
wrterror(const char *p)
{
    const char *q = " error: ";
    malloc_config__diag_writer(mallloc_config__diag_prefix, malloc_config__strlen(mallloc_config__diag_prefix));
    malloc_config__diag_writer(malloc_func, malloc_config__strlen(malloc_func));
    malloc_config__diag_writer(q, malloc_config__strlen(q));
    malloc_config__diag_writer(p, malloc_config__strlen(p));
    suicide = 1;
    malloc_config__abort();
}

static void
wrtwarning(const char *p)
{
    const char *q = " warning: ";
    if (malloc_abort)
	wrterror(p);
    malloc_config__diag_writer(mallloc_config__diag_prefix, malloc_config__strlen(mallloc_config__diag_prefix));
    malloc_config__diag_writer(malloc_func, malloc_config__strlen(malloc_func));
    malloc_config__diag_writer(q, malloc_config__strlen(q));
    malloc_config__diag_writer(p, malloc_config__strlen(p));
}

/*
 * Allocate a number of pages from the OS
 */
static void *
map_pages(int pages)
{
    char* result = (char*)pageround((u_long)emu_sbrk(0));
    char* tail = result + (pages << malloc_pageshift);

    if (emu_brk(tail)) {
#ifdef EXTRA_SANITY
	wrterror("(ES): map_pages fails\n");
#endif /* EXTRA_SANITY */
	return 0;
    }

    last_index = ptr2index(tail) - 1;
    last_brk   = tail;

    if ((last_index+1) >= malloc_ninfo) {
        wrterror("map_pages: invariant error: miscalculated malloc_ninfo\n");
        return 0;
    }

    return result;
}

/*
 * Allocate a number of complete pages
 */
static void *
malloc_pages(size_t size)
{
    void *p, *delay_free = 0;
    struct pgfree *pf;
    u_long index;

    size = pageround(size);

    p = 0;

    /* Look for free pages before asking for more */
    for(pf = free_list.next; pf; pf = pf->next) {

#ifdef EXTRA_SANITY
	if (pf->size & malloc_pagemask)
	    wrterror("(ES): junk length entry on free_list\n");
	if (!pf->size)
	    wrterror("(ES): zero length entry on free_list\n");
	if (pf->page == pf->end)
	    wrterror("(ES): zero entry on free_list\n");
	if (pf->page > pf->end)
	    wrterror("(ES): sick entry on free_list\n");
	if ((void*)pf->page >= (void*)emu_sbrk(0))
	    wrterror("(ES): entry on free_list past brk\n");
	if (page_dir[ptr2index(pf->page)] != MALLOC_FREE)
	    wrterror("(ES): non-free first page on free-list\n");
	if (page_dir[ptr2index(pf->end)-1] != MALLOC_FREE)
	    wrterror("(ES): non-free last page on free-list\n");
#endif /* EXTRA_SANITY */

	if (pf->size < size)
	    continue;

	if (pf->size == size) {
	    p = pf->page;
	    if (pf->next)
		    pf->next->prev = pf->prev;
	    pf->prev->next = pf->next;
	    delay_free = pf;
	    break;
	}

	p = pf->page;
	pf->page = (char *)pf->page + size;
	pf->size -= size;
	break;
    }

#ifdef EXTRA_SANITY
    if (p && page_dir[ptr2index(p)] != MALLOC_FREE)
	wrterror("(ES): allocated non-free page on free-list\n");
#endif /* EXTRA_SANITY */

    size >>= malloc_pageshift;

    /* Map new pages */
    if (!p)
	p = map_pages(size);

    if (p) {

	index = ptr2index(p);
	page_dir[index] = MALLOC_FIRST;
	for (size_t i=1;i<size;i++)
	    page_dir[index+i] = MALLOC_FOLLOW;

	if (malloc_junk)
	    malloc_config__memset(p, SOME_JUNK, size << malloc_pageshift);
    }

    if (delay_free) {
	if (!px)
	    px = delay_free;
	else
	    ifree(delay_free);
    }

    return p;
}

/*
 * Allocate a page of fragments
 */

static __inline__ int
malloc_make_chunks(int bits)
{
    struct  pginfo *bp;
    void *pp;
    int i, k, l;

    /* Allocate a new bucket */
    pp = malloc_pages(malloc_pagesize);
    if (!pp)
	return 0;

    /* Find length of admin structure */
    l = offsetof(struct pginfo, bits[0]);
    l += sizeof bp->bits[0] *
	(((malloc_pagesize >> bits)+MALLOC_BITS-1) / MALLOC_BITS);

    /* Don't waste more than two chunks on this */
    if ((1<<(bits)) <= l+l) {
	bp = (struct  pginfo *)pp;
    } else {
	bp = (struct  pginfo *)imalloc(l);
	if (!bp) {
	    ifree(pp);
	    return 0;
	}
    }

    bp->size = (1<<bits);
    bp->shift = bits;
    bp->total = bp->free = malloc_pagesize >> bits;
    bp->page = pp;

    /* set all valid bits in the bitmap */
    k = bp->total;
    i = 0;

    /* Do a bunch at a time */
    for(;k-i >= (int)MALLOC_BITS; i += (int)MALLOC_BITS)
	bp->bits[i / MALLOC_BITS] = ~0;

    for(; i < k; i++)
        bp->bits[i/MALLOC_BITS] |= 1<<(i%MALLOC_BITS);

    if (bp == bp->page) {
	/* Mark the ones we stole for ourselves */
	for(i=0;l > 0;i++) {
	    bp->bits[i/MALLOC_BITS] &= ~(1<<(i%MALLOC_BITS));
	    bp->free--;
	    bp->total--;
	    l -= (1 << bits);
	}
    }

    page_dir[ptr2index(pp)] = bp;

    bp->next = page_dir[bits];
    page_dir[bits] = bp;

    return 1;
}

/*
 * Allocate a fragment
 */
static void *
malloc_bytes(size_t size)
{
    int i,j;
    u_int u;
    struct  pginfo *bp;
    int k;
    u_int *lp;

    /* Don't bother with anything less than this */
    if (size < malloc_minsize)
	size = malloc_minsize;

    /* Find the right bucket */
    j = 1;
    i = size-1;
    while (i >>= 1)
	j++;

    /* If it's empty, make a page more of that size chunks */
    if (!page_dir[j] && !malloc_make_chunks(j))
	return 0;

    bp = page_dir[j];

    /* Find first word of bitmap which isn't empty */
    for (lp = bp->bits; !*lp; lp++)
	;

    /* Find that bit, and tweak it */
    u = 1;
    k = 0;
    while (!(*lp & u)) {
	u += u;
	k++;
    }
    *lp ^= u;

    /* If there are no more free, remove from free-list */
    if (!--bp->free) {
	page_dir[j] = bp->next;
	bp->next = 0;
    }

    /* Adjust to the real offset of that chunk */
    k += (lp-bp->bits)*MALLOC_BITS;
    k <<= bp->shift;

    if (malloc_junk)
	malloc_config__memset((u_char*)bp->page + k, SOME_JUNK, bp->size);

    return (u_char *)bp->page + k;
}

/*
 * Allocate a piece of memory
 */
static void *
imalloc(size_t size)
{
    void *result;

    if (suicide)
	malloc_config__abort();

    if ((size + malloc_pagesize) < size)	/* Check for overflow */
	result = 0;
    else if (size <= malloc_maxsize)
	result =  malloc_bytes(size);
    else
	result =  malloc_pages(size);

    if (malloc_zero && result)
	malloc_config__memset(result, 0, size);

    return result;
}

/*
 * Change the size of an allocation.
 */
static void *
irealloc(void *ptr, size_t size)
{
    void *p;
    u_long osize, index;
    struct pginfo **mp;
    int i;

    if (suicide)
	malloc_config__abort();

    index = ptr2index(ptr);

    if (index < malloc_pageshift) {
	wrtwarning("junk pointer, too low to make sense.\n");
	return 0;
    }

    if (index > last_index) {
	wrtwarning("junk pointer, too high to make sense.\n");
	return 0;
    }

    mp = &page_dir[index];

    if (*mp == MALLOC_FIRST) {			/* Page allocation */

	/* Check the pointer */
	if ((u_long)ptr & malloc_pagemask) {
	    wrtwarning("modified (page-) pointer.\n");
	    return 0;
	}

	/* Find the size in bytes */
	for (osize = malloc_pagesize; *++mp == MALLOC_FOLLOW;)
	    osize += malloc_pagesize;

        if (!malloc_realloc && 			/* unless we have to, */
	  size <= osize && 			/* .. or are too small, */
	  size > (osize - malloc_pagesize)) {	/* .. or can free a page, */
	    return ptr;				/* don't do anything. */
	}

    } else if (*mp >= MALLOC_MAGIC) {		/* Chunk allocation */

	/* Check the pointer for sane values */
	if (((u_long)ptr & ((*mp)->size-1))) {
	    wrtwarning("modified (chunk-) pointer.\n");
	    return 0;
	}

	/* Find the chunk index in the page */
	i = ((u_long)ptr & malloc_pagemask) >> (*mp)->shift;

	/* Verify that it isn't a free chunk already */
        if ((*mp)->bits[i/MALLOC_BITS] & (1<<(i%MALLOC_BITS))) {
	    wrtwarning("chunk is already free.\n");
	    return 0;
	}

	osize = (*mp)->size;

	if (!malloc_realloc &&		/* Unless we have to, */
	  size < osize && 		/* ..or are too small, */
	  (size > osize/2 ||	 	/* ..or could use a smaller size, */
	  osize == malloc_minsize)) {	/* ..(if there is one) */
	    return ptr;			/* ..Don't do anything */
	}

    } else {
	wrtwarning("pointer to wrong page.\n");
	return 0;
    }

    p = imalloc(size);

    if (p) {
	/* copy the lesser of the two sizes, and free the old one */
	if (!size || !osize)
	    ;
	else if (osize < size)
	    malloc_config__memcpy(p, ptr, osize);
	else
	    malloc_config__memcpy(p, ptr, size);
	ifree(ptr);
    }
    return p;
}

/*
 * Free a sequence of pages
 */

static __inline__ void
free_pages(void *ptr, int index, struct pginfo *info)
{
    struct pgfree *pf, *pt=0;
    void *tail;

    if (info == MALLOC_FREE) {
	wrtwarning("page is already free.\n");
	return;
    }

    if (info != MALLOC_FIRST) {
	wrtwarning("pointer to wrong page.\n");
	return;
    }

    if ((u_long)ptr & malloc_pagemask) {
	wrtwarning("modified (page-) pointer.\n");
	return;
    }

    /* Count how many pages and mark them free at the same time */
    page_dir[index] = MALLOC_FREE;
    int i;
    for (i = 1; page_dir[index+i] == MALLOC_FOLLOW; i++)
	page_dir[index + i] = MALLOC_FREE;

    u_long l = i << malloc_pageshift;

    if (malloc_junk)
	malloc_config__memset(ptr, SOME_JUNK, l);

    tail = (char *)ptr+l;

    /* add to free-list */
    if (!px)
	px = imalloc(sizeof *pt);	/* This cannot fail... */
    px->page = ptr;
    px->end =  tail;
    px->size = l;
    if (!free_list.next) {

	/* Nothing on free list, put this at head */
	px->next = free_list.next;
	px->prev = &free_list;
	free_list.next = px;
	pf = px;
	px = 0;

    } else {

	/* Find the right spot, leave pf pointing to the modified entry. */
	tail = (char *)ptr+l;

	for(pf = free_list.next; pf->end < ptr && pf->next; pf = pf->next)
	    ; /* Race ahead here */

	if (pf->page > tail) {
	    /* Insert before entry */
	    px->next = pf;
	    px->prev = pf->prev;
	    pf->prev = px;
	    px->prev->next = px;
	    pf = px;
	    px = 0;
	} else if (pf->end == ptr ) {
	    /* Append to the previous entry */
	    pf->end = (char *)pf->end + l;
	    pf->size += l;
	    if (pf->next && pf->end == pf->next->page ) {
		/* And collapse the next too. */
		pt = pf->next;
		pf->end = pt->end;
		pf->size += pt->size;
		pf->next = pt->next;
		if (pf->next)
		    pf->next->prev = pf;
	    }
	} else if (pf->page == tail) {
	    /* Prepend to entry */
	    pf->size += l;
	    pf->page = ptr;
	} else if (!pf->next) {
	    /* Append at tail of chain */
	    px->next = 0;
	    px->prev = pf;
	    pf->next = px;
	    pf = px;
	    px = 0;
	} else {
	    wrterror("freelist is destroyed.\n");
	}
    }

    /* Return something to OS ? */
    if (!pf->next &&				/* If we're the last one, */
      pf->size > malloc_cache &&		/* ..and the cache is full, */
      pf->end == last_brk &&			/* ..and none behind us, */
      last_brk == emu_sbrk(0)) {		/* ..and it's OK to do... */

	/*
	 * Keep the cache intact.  Notice that the '>' above guarantees that
	 * the pf will always have at least one page afterwards.
	 */
	pf->end = (char *)pf->page + malloc_cache;
	pf->size = malloc_cache;

	emu_brk(pf->end);
	last_brk = pf->end;

	index = ptr2index(pf->end);
	last_index = index - 1;

	for(i=index;(u_long)i <= last_index;)
	    page_dir[i++] = MALLOC_NOT_MINE;

	/* XXX: We could realloc/shrink the pagedir here I guess. */
    }
    if (pt)
	ifree(pt);
}

/*
 * Free a chunk, and possibly the page it's on, if the page becomes empty.
 */

static __inline__ void
free_bytes(void *ptr, int index, struct pginfo *info)
{
    (void)index;

    int i;
    struct pginfo **mp;
    void *vp;

    /* Find the chunk number on the page */
    i = ((u_long)ptr & malloc_pagemask) >> info->shift;

    if (((u_long)ptr & (info->size-1))) {
	wrtwarning("modified (chunk-) pointer.\n");
	return;
    }

    if (info->bits[i/MALLOC_BITS] & (1<<(i%MALLOC_BITS))) {
	wrtwarning("chunk is already free.\n");
	return;
    }

    if (malloc_junk)
	malloc_config__memset(ptr, SOME_JUNK, info->size);

    info->bits[i/MALLOC_BITS] |= 1<<(i%MALLOC_BITS);
    info->free++;

    mp = page_dir + info->shift;

    if (info->free == 1) {

	/* Page became non-full */

	mp = page_dir + info->shift;
	/* Insert in address order */
	while (*mp && (*mp)->next && (*mp)->next->page < info->page)
	    mp = &(*mp)->next;
	info->next = *mp;
	*mp = info;
	return;
    }

    if (info->free != info->total)
	return;

    /* Find & remove this page in the queue */
    while (*mp != info) {
	mp = &((*mp)->next);
#ifdef EXTRA_SANITY
	if (!*mp)
		wrterror("(ES): Not on queue\n");
#endif /* EXTRA_SANITY */
    }
    *mp = info->next;

    /* Free the page & the info structure if need be */
    page_dir[ptr2index(info->page)] = MALLOC_FIRST;
    vp = info->page;		/* Order is important ! */
    if(vp != (void*)info)
	ifree(info);
    ifree(vp);
}

static void
ifree(void *ptr)
{
    struct pginfo *info;
    int index;

    /* This is legal */
    if (!ptr)
	return;

    /* If we're already sinking, don't make matters any worse. */
    if (suicide)
	return;

    index = ptr2index(ptr);

    if (index < (int)malloc_pageshift) {
	wrtwarning("junk pointer, too low to make sense.\n");
	return;
    }

    if (index > (int)last_index) {
	wrtwarning("junk pointer, too high to make sense.\n");
	return;
    }

    info = page_dir[index];

    if (info < MALLOC_MAGIC)
        free_pages(ptr, index, info);
    else
	free_bytes(ptr, index, info);
    return;
}

static __inline__ void
malloc_init_done_check()
{
    if (!malloc_started) {
	wrterror("malloc_init() never called!\n");
    }
}

/*
 * These are the public exported interface routines.
 */

/*
 * Initialize the world
 */
void
malloc_init(void* base, size_t size)
{
    malloc_config__thread_lock();

    malloc_func = " in malloc_init():";

    if (malloc_started) {
	wrterror("malloc_init() called twice!\n");
    }

#ifdef EXTRA_SANITY
    malloc_junk = 1;
#endif /* EXTRA_SANITY */

    const char* p = malloc_options;
    for (; p && *p; p++) {
        switch (*p) {
        case '>': malloc_cache   <<= 1; break;
        case '<': malloc_cache   >>= 1; break;
        case 'a': malloc_abort   = 0; break;
        case 'A': malloc_abort   = 1; break;
        case 'r': malloc_realloc = 0; break;
        case 'R': malloc_realloc = 1; break;
        case 'j': malloc_junk    = 0; break;
        case 'J': malloc_junk    = 1; break;
        case 'v': malloc_sysv    = 0; break;
        case 'V': malloc_sysv    = 1; break;
        case 'x': malloc_xmalloc = 0; break;
        case 'X': malloc_xmalloc = 1; break;
        case 'z': malloc_zero    = 0; break;
        case 'Z': malloc_zero    = 1; break;
        default: {
            int tmp = malloc_abort;
            malloc_abort = 0;
            wrtwarning("unknown char in malloc_options string\n");
            malloc_abort = tmp;
            break;
        }
        }
    }

    /*
     * We want junk in the entire allocation, and zero only in the part
     * the user asked for.
     */
    if (malloc_zero)
	malloc_junk=1;

    /*
     * If we run with junk (or implicitly from above: zero), we want to
     * force realloc() to get new storage, so we can DTRT with it.
     */
    if (malloc_junk)
	malloc_realloc=1;

    malloc_heap_start = base;
    malloc_heap_end   = (char*)base + size;
    malloc_heap_brk   = base;

    /* Number of page entries that are needed given the heap_size. */
    malloc_ninfo = (size / malloc_pagesize) + malloc_pageshift;

    if (emu_brk((void*)pgdirround((u_long)emu_sbrk(0)))) {
        wrterror("failed to align heap block for page directory\n");
    }

    page_dir = emu_sbrk(malloc_ninfo * sizeof(struct pginfo*));
    if ((long)page_dir == -1) {
        wrterror("failed to allocate page directory from heap block\n");
    }

    /*
     * We need a maximum of malloc_pageshift buckets, steal these from the
     * front of the page_directory;
     */
    malloc_origo = ((u_long)pageround((u_long)emu_sbrk(0))) >> malloc_pageshift;
    malloc_origo -= malloc_pageshift;

    /* Recalculate the cache size in bytes, and make sure it's nonzero */

    if (!malloc_cache)
	malloc_cache++;

    malloc_cache <<= malloc_pageshift;

    /*
     * This is a nice hack from Kaleb Keithly (kaleb@x.org).
     * We can sbrk(2) further back when we keep this on a low address.
     */
    px = (struct pgfree *) imalloc (sizeof *px);

    /* Been here, done that */
    malloc_started = 1;

    malloc_config__thread_unlock();
}

void *
malloc(size_t size)
{
    malloc_config__thread_lock();

    malloc_init_done_check();

    malloc_func = " in malloc():";
    if (malloc_active++) {
	wrtwarning("recursive call.\n");
        malloc_active--;
        malloc_config__thread_unlock();
	return (0);
    }
    void * r = (malloc_sysv && !size) ? 0 : imalloc(size);
    malloc_active--;
    malloc_config__thread_unlock();
    if (malloc_xmalloc && !r)
	wrterror("out of memory.\n");
    return (r);
}

void
free(void *ptr)
{
    malloc_config__thread_lock();

    malloc_init_done_check();

    malloc_func = " in free():";
    if (malloc_active++) {
	wrtwarning("recursive call.\n");
	malloc_active--;
        malloc_config__thread_unlock();
	return;
    } else {
	ifree(ptr);
    }
    malloc_active--;
    malloc_config__thread_unlock();
    return;
}

void *
realloc(void *ptr, size_t size)
{
    malloc_config__thread_lock();

    malloc_init_done_check();

    malloc_func = " in realloc():";
    if (malloc_active++) {
	wrtwarning("recursive call.\n");
        malloc_active--;
        malloc_config__thread_unlock();
	return (0);
    }
    void* r;
    if (malloc_sysv && !size) {
	ifree(ptr);
	r = 0;
    } else if (!ptr) {
	r = imalloc(size);
    } else {
        r = irealloc(ptr, size);
    }
    malloc_active--;
    malloc_config__thread_unlock();
    if (malloc_xmalloc && !r)
	wrterror("out of memory.\n");
    return (r);
}

void *
calloc(size_t nmemb, size_t size)
{
    const size_t n = nmemb * size;
    void* r = malloc(n);
    if (r) {
        malloc_config__memset(r, 0, n);
    }
    return r;
}
