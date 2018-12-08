#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

#include "bnode.h"
#include "buf.h"

int
test_bnode()
{
	bnode_t *b, *b2;
	json_object *j, *v;
	char *bin = "binary data";
	int len = strlen(bin);
	buf_t *buf;

	b = malloc(sizeof(bnode_t));
	b->desc = "Test";

	j = json_object_new_object();

	v = json_object_new_string("val1");
	json_object_object_add(j, "key1", v);

	v = json_object_new_string("val2");
	json_object_object_add(j, "key2", v);

	b->attr = j;
	b->type = BNODE_BINARY;
	b->data.bytes = (unsigned char *) bin;
	b->len = len;

	buf = bnode_to_buf(b);
	buf_hexdump(buf);
	b2 = bnode_from_buf(buf);
	bnode_print(b, 0);
	bnode_print(b2, 0);

	return 0;
}

int main()
{
	test_bnode();
	return 0;
}
