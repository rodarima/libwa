#ifndef _BNODE_H_
#define _BNODE_H_

#include <json-c/json.h>

#include "msg.h"
#include "buf.h"

enum bnode_type {
	BNODE_EMPTY = 0,
	BNODE_STRING,
	BNODE_INT,
	BNODE_LIST,
	BNODE_BINARY
};

struct bnode_t {
	char *desc;

	struct json_object *attr;

	int len;

	enum bnode_type type;
	union content {
		struct bnode_t **list;
		unsigned char *bytes;
		int number;
		char *str;
	} data;
};

typedef struct bnode_t bnode_t;

//int
//bnode_print_msg(msg_t *msg);
int
bnode_print(bnode_t *bn, int indent);

bnode_t *
bnode_from_buf(const buf_t *buf);

buf_t *
bnode_to_buf(bnode_t *b);

#endif
