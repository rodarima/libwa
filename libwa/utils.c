#include "utils.h"
#include <stdlib.h>

/* Wrap malloc family into a more safe way, aborting in case we get NULL */
void *
safe_malloc(size_t size)
{
	void *p = malloc(size);
	if(!p) abort();
	return p;
}

void *
safe_calloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if(!p) abort();
	return p;
}
