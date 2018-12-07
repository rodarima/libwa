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
	int i,j;
	for(i=0; i< 1 + (len-1)/16; i++)
	{
		for(j=0; j<16; j++)
		{
			int p = i*16 + j;
			if(p < len)
				printf("%02X ", (unsigned char) buf[p]);
			else
				printf("   ");

			if(j == 7)
				printf(" ");
		}
		printf("  ");
		for(j=0; j<16; j++)
		{
			int p = i*16 + j;
			if(p < len)
			{
				if(isprint(buf[p]))
					printf("%c", buf[p]);
				else
					printf(".");
			}
			else
			{
				break;
			}
		}
		printf("\n");
	}
}


void
buf_hexdump(buf_t *buf)
{
	hexdump(buf->ptr, buf->len);
}
