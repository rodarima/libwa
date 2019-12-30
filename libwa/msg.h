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

enum { LAYER0, LAYER1, LAYER2, LAYER3, LAYER4 };
enum {
	DMSG_USE_TAG = 1,
};

enum { DMSG_NORMAL, DMSG_RELAY };

typedef struct
{
	/* Layer src and dst */
	int src;
	int dst;

	/* Optional flags */
	int flags;

	int type;

	/* Msg */
	msg_t *msg;
} dmsg_t;
