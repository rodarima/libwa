#include "buf.h"

#include <assert.h>
#include <stdio.h>
#include <ctype.h>

buf_t *
buf_init(const size_t len)
{
	buf_t *buf;

	assert(len > 0);
	buf = malloc(sizeof(buf_t));
	assert(buf);
	buf->ptr = malloc(len);
	assert(buf->ptr);
	buf->len = len;

	return buf;
}

void
buf_free(buf_t *buf)
{
	free(buf->ptr);
	free(buf);
}

void
hexdump(const unsigned char *buf, const size_t len)
{
	size_t i,j,p;

	if(len == 0)
		return;

	for(i=0; i< 1 + (len-1)/16; i++)
	{
		for(j=0; j<16; j++)
		{
			p = i*16 + j;
			if(p < len)
				fprintf(stderr, "%02X ", (unsigned char) buf[p]);
			else
				fprintf(stderr, "   ");

			if(j == 7)
				fprintf(stderr, " ");
		}
		fprintf(stderr, "  ");
		for(j=0; j<16; j++)
		{
			p = i*16 + j;
			if(p < len)
			{
				if(isprint(buf[p]))
					fprintf(stderr, "%c", buf[p]);
				else
					fprintf(stderr, ".");
			}
			else
			{
				break;
			}
		}
		fprintf(stderr, "\n");
	}
}


void
buf_hexdump(buf_t *buf)
{
	hexdump(buf->ptr, buf->len);
}
