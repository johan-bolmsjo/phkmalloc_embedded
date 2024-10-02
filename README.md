Hacked phkmalloc for embedded demo purpose.

phkmalloc is an old school simple malloc implementation that was used in FreeBSD
up to version 6. It's certainly not the fastest, does not scale with preemptive
threading, but is quite simple and resilient.

Added calloc function for completeness.

There is `malloc`, `calloc`, `realloc` and `free` functions. `malloc_init` must
be run once before any of them are called (include malloc.h). Target
configuration is done in `malloc_config.h`; defaults are for a Posix
environment.

malloc.pdf comes from http://phk.freebsd.dk/pubs/malloc.pdf

Keff keff.
