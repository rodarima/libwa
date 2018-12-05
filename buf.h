#pragma once

#include <stdlib.h>

typedef struct
{
	size_t len;
	unsigned char *ptr;
} buf_t;

buf_t *
buf_init(size_t len);

void
buf_free(buf_t *buf);

void
buf_hexdump(buf_t *buf);

void
hexdump(const unsigned char *buf, const size_t len);

