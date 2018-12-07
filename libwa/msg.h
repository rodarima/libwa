#pragma once

#include <string.h>

typedef struct
{
	/* We assume tag is always a string */
	char *tag;

	/* Whereas cmd can be binary data */
	size_t len;
	void *cmd;
	int is_text;
} msg_t;
