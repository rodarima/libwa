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

int
bnode_summary(bnode_t *bn, int indent);

bnode_t *
bnode_from_buf(const buf_t *buf);

buf_t *
bnode_to_buf(bnode_t *b);

void
bnode_free(bnode_t *b);

int
bnode_attr_add(bnode_t *b, char *key, char *val);

const char *
bnode_attr_get(bnode_t *bn, const char *key);

int
bnode_attr_exists(bnode_t *bn, const char *key, const char *value);

#endif
