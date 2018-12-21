#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <json-c/json.h>

#include "bnode.h"
#include "crypto.h"
#include "buf.h"

#define DEBUG LOG_LEVEL_INFO
#include "log.h"

int
test_bnode()
{
	bnode_t *b, *b2;
	json_object *j, *v;
	char *bin = "binary data";
	int len = strlen(bin);
	buf_t *buf;

	b = malloc(sizeof(bnode_t));
	b->desc = strdup("Test");

	j = json_object_new_object();

	v = json_object_new_string("val1");
	json_object_object_add(j, "key1", v);

	v = json_object_new_string("val2");
	json_object_object_add(j, "key2", v);

	b->attr = j;
	b->type = BNODE_BINARY;
	b->data.bytes = (unsigned char *) strdup(bin);
	b->len = len;

	buf = bnode_to_buf(b);
	buf_hexdump(buf);
	b2 = bnode_from_buf(buf);
	bnode_print(b, 0);
	bnode_print(b2, 0);

	buf_free(buf);
	bnode_free(b);
	bnode_free(b2);

	return 0;
}

int
test_encrypt()
{
	int ret = 0;
	crypto_t *c = malloc(sizeof(*c));
	buf_t *in, *out, *dec, *enc_key;
	char *data = "Esto es una prueba de información que será cifrada y, quizás, "
		"descifrada con éxito";

	in = buf_init(strlen(data) + 1);
	strcpy((char *) in->ptr, data);

	enc_key = buf_init(32);
	memset(enc_key->ptr, 0x01, 32);
	c->enc_key = enc_key;
	c->mac_key = enc_key;

	out = crypto_encrypt_buf(c, in);
	dec = crypto_decrypt_buf(c, out);

	/* TODO: HMAC */

	ret |= (dec->len != in->len);
	ret |= memcmp(data, dec->ptr, dec->len) ? 1 : 0;

	buf_free(out);
	buf_free(in);
	buf_free(dec);
	buf_free(enc_key);
	free(c);

	return ret;
}

int main()
{
	test_bnode();
	assert(!test_encrypt());
	return 0;
}
