#pragma once
#include <stddef.h>

/* Wrap malloc family into a more safe way, aborting in case we get NULL */
void *
safe_malloc(size_t size);

void *
safe_calloc(size_t nmemb, size_t size);

/* Also destroy the pointer inmediately after freeing it */

#define safe_free(x) do {						\
	void **__ptr = &(x);						\
	free(*__ptr);							\
	*__ptr = NULL;							\
} while(0);
