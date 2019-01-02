#include <stdio.h>
#include <assert.h>
#include <json-c/json.h>

#include "bnode.h"
#include "msg.h"
#include "crypto.h"

#define DEBUG LOG_LEVEL_ERR

#include "log.h"

enum tag_t
{
	TAG_LIST_EMPTY      = 0,
	TAG_STREAM_END      = 2,
	TAG_DICTIONARY_0    = 236,
	TAG_DICTIONARY_1    = 237,
	TAG_DICTIONARY_2    = 238,
	TAG_DICTIONARY_3    = 239,
	TAG_LIST_8          = 248,
	TAG_LIST_16         = 249,
	TAG_JID_PAIR        = 250,
	TAG_HEX_8           = 251,
	TAG_BINARY_8        = 252,
	TAG_BINARY_20       = 253,
	TAG_BINARY_32       = 254,
	TAG_NIBBLE_8        = 255,
	TAG_SINGLE_BYTE_MAX = 256,
	TAG_PACKED_MAX      = 254,
};

/* We don't actually need those tokens to be strings, as we can use an
 * identifier for each one. Most of them are used only as tags, to be later
 * compared with strcmp() with the overhead added.
 *
 * Let's wait until we can identify the slowest part (Knuth).
 */


char *token_table[] = {
	NULL,NULL,NULL,"200","400","404","500","501","502","action","add",
	"after","archive","author","available","battery","before","body",
	"broadcast","chat","clear","code","composing","contacts","count",
	"create","debug","delete","demote","duplicate","encoding","error",
	"false","filehash","from","g.us","group","groups_v2","height","id",
	"image","in","index","invis","item","jid","kind","last","leave",
	"live","log","media","message","mimetype","missing","modify","name",
	"notification","notify","out","owner","participant","paused",
	"picture","played","presence","preview","promote","query","raw",
	"read","receipt","received","recipient","recording","relay",
	"remove","response","resume","retry","s.whatsapp.net"/*"c.us"*/,"seconds",
	"set","size","status","subject","subscribe","t","text","to","true",
	"type","unarchive","unavailable","url","user","value","web","width",
	"mute","read_only","admin","creator","short","update","powersave",
	"checksum","epoch","block","previous","409","replaced","reason",
	"spam","modify_tag","message_info","delivery","emoji","title",
	"description","canonical-url","matched-text","star","unstar",
	"media_key","filename","identity","unread","page","page_count",
	"search","media_message","security","call_log","profile","ciphertext",
	"invite","gif","vcard","frequent","privacy","blacklist","whitelist",
	"verify","location","document","elapsed","revoke_invite","expiration",
	"unsubscribe","disable","vname","old_jid","new_jid","announcement",
	"locked","prop","label","color","call","offer","call-id"
};

typedef struct {
	unsigned char *start;
	unsigned char *ptr;
	unsigned char *end;
	size_t len;
} parser_t;

char nibble_table[] = {
	'0','1','2','3','4','5','6','7','8','9','-','.','\0','\0','\0','\0',
};
char hex_table[] = {
	'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
};

char *bnode_type_str[] = { "empty", "string", "int", "list", "binary" };


int
handle(bnode_t *bn);

bnode_t *
read_bnode(parser_t *p);

char *
read_string(parser_t *p, int tag);

int
bnode_print(bnode_t *bn, int indent);

static int
bnode_compile(parser_t *p, bnode_t *b);






int
write_byte(parser_t *p, size_t byte)
{
	if(p->start)
		*p->ptr++ = byte;
	else
		p->len++;

	return 0;
}

int
write_binary_buf(parser_t *p, const unsigned char *buf, size_t len)
{
	if(p->start)
	{
		memcpy(p->ptr, buf, len);
		p->ptr += len;
	}
	else
	{
		p->len += len;
	}

	return 0;
}

int
write_int(parser_t *p, size_t len, size_t v)
{
	/* Always big endian */

	int i;

	assert((0 < len) && (len <= 4));

	if(!p->start)
	{
		p->len += len;
		return 0;
	}

	assert(p->ptr + len <= p->end);

	for(i=0; i < len; i++)
	{
		p->ptr[len-1-i] = v & 0xFF;
		v = v >> 8;
	}

	p->ptr += len;

	return 0;
}

int
write_int32(parser_t *p, size_t v)
{
	return write_int(p, 4, v);
}

int
write_int20(parser_t *p, size_t v)
{
	return write_int(p, 3, v & 0x0FFFFF);
}

int
write_int16(parser_t *p, size_t v)
{
	return write_int(p, 2, v);
}

int
write_binary_len(parser_t *p, size_t len)
{
	if(len >= (1<<20))
	{
		write_byte(p, TAG_BINARY_32);
		write_int32(p, len);
	}
	else if(len >= (1<<8))
	{
		write_byte(p, TAG_BINARY_20);
		write_int20(p, len);
	}
	else
	{
		write_byte(p, TAG_BINARY_8);
		write_byte(p, len);
	}

	return 0;
}

int
write_binary(parser_t *p, const unsigned char *buf, size_t len)
{
	/* Writes the following:
	 * [binary tag] [len] [buf]
	 */

	write_binary_len(p, len);
	write_binary_buf(p, buf, len);
	return 0;
}

int
write_string(parser_t *p, const char *s)
{
	size_t len;

	len = strlen(s);
	write_binary(p, (unsigned char *) s, len);
	return 0;
}

int
write_list_head(parser_t *p, size_t len)
{
	if(len == 0)
	{
		write_byte(p, TAG_LIST_EMPTY);
	}
	else if (len < 256)
	{
		write_byte(p, TAG_LIST_8);
		write_int(p, 1, len);
	}
	else
	{
		write_byte(p, TAG_LIST_16);
		write_int(p, 2, len);
	}
	return 0;
}

int
write_attr(parser_t *p, json_object *attr)
{
	const char *val;

	json_object_object_foreach(attr, key, val_obj)
	{
		val = json_object_get_string(val_obj);
		write_string(p, key);
		write_string(p, val);
	}

	return 0;
}

int
write_bnode_list(parser_t *p, bnode_t **list, size_t len)
{
	int i;

	write_list_head(p, len);

	for(i=0; i<len; i++)
	{
		bnode_compile(p, list[i]);
	}

	return 0;
}

int
write_content(parser_t *p, bnode_t *b)
{
	switch(b->type)
	{
		case BNODE_EMPTY:
			return 0;
		case BNODE_STRING:
		case BNODE_INT:
		case BNODE_LIST:
			write_bnode_list(p, b->data.list, b->len);
			return 0;
		case BNODE_BINARY:
			write_binary(p, b->data.bytes, b->len);
			return 0;
		default:
			LOG_ERR("Unknown type '%s'\n",
					bnode_type_str[b->type]);
			abort();
			return -1;

	}

	return -1;
}

static int
bnode_compile(parser_t *p, bnode_t *b)
{
	size_t size;

	/* The description */
	size = 1;
	/* Attributes */
	if(b->attr)
		size += 2 * json_object_object_length(b->attr);
	/* Content */
	size += (b->type == BNODE_EMPTY) ? 0 : 1;

	write_list_head(p, size);

	write_string(p, b->desc);

	if(b->attr)
		write_attr(p, b->attr);

	if(b->type != BNODE_EMPTY)
		write_content(p, b);

	return 0;
}


buf_t *
bnode_to_buf(bnode_t *b)
{
	parser_t *p;
	buf_t *buf;

	p = calloc(1, sizeof(parser_t));

	/* First step: Compute the length of the bnode */
	bnode_compile(p, b);

	/* Second step: Alloc the exact memory */
	LOG_DEBUG("Computed length is %lu bytes\n", p->len);
	buf = buf_init(p->len);
	p->start = buf->ptr;
	p->ptr = p->start;
	p->end = p->start + p->len;

	/* Finally: fill the buffer with the bnode */
	bnode_compile(p, b);

	free(p);

	return buf;
}

int
bnode_attr_add(bnode_t *b, char *key, char *val)
{
	json_object *val_json;

	if(!b->attr)
		b->attr = json_object_new_object();

	val_json = json_object_new_string(val);
	json_object_object_add(b->attr, key, val_json);

	return 0;
}



int
read_int(parser_t *p, size_t len)
{
	int i, v = 0;

	assert((0 < len) && (len <= 4));
	assert(p->ptr + len <= p->end);

	v = p->ptr[0];
	LOG_DEBUG("v=%02X (%d) len=%ld\n", v, v, len);

	for(i=1; i < len; i++)
	{
		v = v << 8;
		v |= p->ptr[i];
	}

	p->ptr += len;

	return v;
}

int
list_size(parser_t *p, int tag)
{
	switch(tag)
	{
		case TAG_LIST_EMPTY:
			return 0;
		case TAG_LIST_8:
			return read_int(p, 1);
		case TAG_LIST_16:
			return read_int(p, 2);
		default:
			LOG_ERR("Invalid tag %d for list at %p\n",
					tag, p->ptr);
			return -1;
	}

	/* Not reached */
	return -2;
}

unsigned char *
read_bytes(parser_t *p, int len)
{
	LOG_DEBUG("len = %d\n", len);
	assert(p->ptr + len <= p->end);

	unsigned char *s = malloc(len + 1);
	assert(s);

	memcpy(s, p->ptr, len);
	s[len] = '\0';

	p->ptr += len;

	/* We assume a NULL terminated string is wanted here */

	return s;
}

char *
read_packed(parser_t *p, char table[])
{
	int i, j, start, bytes, len, b, nibble;
	char *buf;

	start = read_int(p, 1);

	bytes = start & 0x7F;
	len = bytes * 2;
	buf = malloc(len + 1);
	assert(buf);

	j=0;

	for(i=0; i < bytes; i++)
	{
		b = read_int(p, 1);
		nibble = (b & 0xF0) >> 4;
		buf[j++] = nibble_table[nibble];
		nibble = b & 0x0F;
		buf[j++] = nibble_table[nibble];
	}

	/* The original code has this part switched, but it makes no sense */
	if(start & 0x80)
		len--;

	buf[len] = '\0';

	return buf;
}

char *
read_nibbles(parser_t *p)
{
	return read_packed(p, nibble_table);
}

char *
read_hex(parser_t *p)
{
	return read_packed(p, hex_table);
}

char *
read_jid_pair(parser_t *p)
{
	int len;
	char *user, *server, *jid;

	user = read_string(p, read_int(p, 1));
	assert(user);

	server = read_string(p, read_int(p, 1));
	assert(server);

	len = strlen(user) + 1 + strlen(server);
	jid = malloc(len + 1);
	assert(jid);

	strcpy(jid, user);
	strcat(jid, "@");
	strcat(jid, server);

	assert(jid[len] == '\0');

	free(user);
	free(server);

	return jid;
}

char *
read_string(parser_t *p, int tag)
{
	/*
	 * By some reason, the server parts gets rewritten:
	 *
	 * 	char *token = token_table[tag];
	 *	if(strcmp(token, "s.whatsapp.net") == 0)
	 *		return "c.us";
	 *	return token;
	 *
	 * Neither of both hosts seem to be alive at this time (2018-10-31)
	 *
	 * I simply changed the host in the token_table.
	 */

	if((tag >= 3) && (tag <= 235))
		return strdup(token_table[tag]);

	switch(tag)
	{
		case TAG_JID_PAIR:
			return read_jid_pair(p);

		case TAG_NIBBLE_8:
			return read_nibbles(p);
		case TAG_HEX_8:
			return read_hex(p);

			/* Are these used? */
		case TAG_BINARY_8:
			return (char *)read_bytes(p, read_int(p, 1));
		case TAG_BINARY_20:
			return (char *)read_bytes(p, read_int(p, 3) & 0x000FFFFF);
		case TAG_BINARY_32:
			return (char *)read_bytes(p, read_int(p, 4));
		case TAG_LIST_EMPTY:
			return NULL;

		case TAG_DICTIONARY_0:
		case TAG_DICTIONARY_1:
		case TAG_DICTIONARY_2:
		case TAG_DICTIONARY_3:
			/* Not implemented */
			assert(0);

			/* Read one byte */
			read_int(p, 1);

			/* This will likely fail, as probably there is more data
			 * to be parsed */
			return "<TAG_DICTIONARY: NOT IMPLEMENTED>";
		default:
			return NULL;
	}

	/* Not reached */
	return NULL;
}

json_object *
read_attr(parser_t *p, int len)
{
	int i;
	char *key, *val;
	json_object *val_json;

	if(len == 0)
		return NULL;

	json_object *obj = json_object_new_object();

	for(i=0; i<len; i++)
	{
		LOG_DEBUG("--- New attr ---\n");
		key = read_string(p, read_int(p, 1));
		LOG_DEBUG("key = %s\n", key);
		val = read_string(p, read_int(p, 1));
		LOG_DEBUG("attr %s : %s\n", key, val);
		val_json = json_object_new_string(val);
		json_object_object_add(obj, key, val_json);
		free(key);
		free(val);
	}

	return obj;
}

int
bnode_string(parser_t *p, bnode_t *bn, char *str)
{
	bn->type = BNODE_STRING;
	bn->len = strlen(str);
	bn->data.str = str;

	return 0;
}

int
bnode_packed(parser_t *p, bnode_t *bn)
{
	char *jid = read_jid_pair(p);
	return bnode_string(p, bn, jid);
}

int
bnode_hex(parser_t *p, bnode_t *bn)
{
	char *str = read_hex(p);
	return bnode_string(p, bn, str);
}

int
bnode_nibbles(parser_t *p, bnode_t *bn)
{
	char *str = read_nibbles(p);
	return bnode_string(p, bn, str);
}

int
bnode_jid_pair(parser_t *p, bnode_t *bn)
{
	char *jid = read_jid_pair(p);
	return bnode_string(p, bn, jid);
}

int
bnode_binary(parser_t *p, bnode_t *bn, int tag)
{
	int len;

	switch(tag)
	{
		case TAG_BINARY_8:
			len = read_int(p, 1);
			break;
		case TAG_BINARY_20:
			/* Why they crop the first 4 bits? No idea */
			len = read_int(p, 3) & 0x000FFFFF;
			break;
		case TAG_BINARY_32:
			len = read_int(p, 4);
			break;
	};

	bn->len = len;
	bn->type = BNODE_BINARY;
	bn->data.bytes = read_bytes(p, len);

	return 0;
}

int
bnode_list(parser_t *p, bnode_t *bn, int tag)
{
	int i, size;

	size = list_size(p, tag);

	bn->type = BNODE_LIST;
	bn->data.list = (bnode_t **) malloc(sizeof(bnode_t *) * size);
	bn->len = size;

	for(i=0; i<size; i++)
	{
		bn->data.list[i] = read_bnode(p);
	}

	return 0;
}

int
parse_content(parser_t *p, bnode_t *bn, int tag)
{
	switch(tag)
	{
		case TAG_BINARY_8:
		case TAG_BINARY_20:
		case TAG_BINARY_32:
			LOG_DEBUG("BNODE BINARY\n");
			return bnode_binary(p, bn, tag);
		case TAG_LIST_EMPTY:
		case TAG_LIST_8:
		case TAG_LIST_16:
			LOG_DEBUG("BNODE LIST\n");
			return bnode_list(p, bn, tag);
		case TAG_JID_PAIR:
			LOG_DEBUG("BNODE JID\n");
			return bnode_jid_pair(p, bn);
		case TAG_NIBBLE_8:
			LOG_DEBUG("BNODE NIBBLE\n");
			return bnode_nibbles(p, bn);
		case TAG_HEX_8:
			LOG_DEBUG("BNODE HEX\n");
			return bnode_hex(p, bn);
		default:
			LOG_ERR("Unknown content tag %d\n", tag);
			return -1;
	}

	/* Not reached */
	return -2;
}

void
bnode_free(bnode_t *b)
{
	int i;

	if(b->desc)
		free(b->desc);

	if(b->attr)
	{
		json_object_put(b->attr);
	}

	switch(b->type)
	{
		case BNODE_STRING:
			free(b->data.str);
			break;
		case BNODE_BINARY:
			free(b->data.bytes);
			break;
		case BNODE_LIST:
			for(i=0; i < b->len; i++)
				bnode_free(b->data.list[i]);
			free(b->data.list);
			break;
		default:
			break;
	}

	free(b);
}

const char *
bnode_attr_get(bnode_t *bn, const char *key)
{
	json_object *jval;
	const char *val;

	if(!bn->attr)
		return NULL;


	jval = json_object_object_get(bn->attr, key);
	if(!jval)
		return NULL;

	val = json_object_get_string(jval);
	assert(val);

	return val;
}

int
bnode_attr_exists(bnode_t *bn, const char *key, const char *value)
{
	json_object *jval;
	const char *val;

	if(!bn->attr)
		return 0;


	jval = json_object_object_get(bn->attr, key);
	if(!jval)
		return 0;

	val = json_object_get_string(jval);
	assert(val);

	if(strcmp(val, value) != 0)
		return 0;

	return 1;
}

bnode_t *
read_bnode(parser_t *p)
{
	bnode_t *bn;
	int tag, desc_tag, size, attr_len;

	bn = calloc(sizeof(bnode_t), 1);
	assert(bn);

	bn->type = BNODE_EMPTY;

	tag = read_int(p, 1);
	LOG_DEBUG("TAG:%d\n", tag);
	size = list_size(p, tag);
	LOG_DEBUG("SIZE:%d\n", size);
	desc_tag = read_int(p, 1);

	if(desc_tag == TAG_STREAM_END)
		return NULL;

	bn->desc = read_string(p, desc_tag);
	LOG_DEBUG("DESC:%s\n", bn->desc);

	attr_len = (size - 1) / 2;

	LOG_DEBUG("size=%d, attr_len=%d\n", size, attr_len);

	bn->attr = read_attr(p, attr_len);

	if((size % 2) == 0)
	{
		tag = read_int(p, 1);
		parse_content(p, bn, tag);
	}

	return bn;
}

bnode_t *
bnode_from_buf(const buf_t *buf)
{
	parser_t *p;
	bnode_t *bn;

	p = malloc(sizeof(parser_t));
	p->start = buf->ptr;
	p->ptr = p->start;
	p->end = p->start + buf->len;
	LOG_DEBUG("bnode buf len:%ld\n", buf->len);

	bn = read_bnode(p);
#if (DEBUG >= LOG_LEVEL_DEBUG)
	bnode_print(bn, 0);
#endif
	free(p);

	return bn;
}

int
print_attr(bnode_t *bn, int indent)
{
	char *pad = malloc(indent + 1);
	int i;

	for(i=0; i<indent; i++)
	{
		pad[i] = ' ';
	}
	pad[indent] = '\0';

	struct json_object_iterator it;
	struct json_object_iterator it_end;
	struct json_object* obj;

	obj = bn->attr;
	it = json_object_iter_begin(obj);
	it_end = json_object_iter_end(obj);

	fprintf(stderr, "%sattr:\n", pad);
	fprintf(stderr, "%s{\n", pad);

	while (!json_object_iter_equal(&it, &it_end))
	{
		fprintf(stderr, "%s  %s : %s\n",
				pad,
				json_object_iter_peek_name(&it),
				json_object_get_string(
					json_object_iter_peek_value(&it)));

		json_object_iter_next(&it);
	}

	fprintf(stderr, "%s}\n", pad);
	free(pad);

	return 0;
}

int
bnode_summary(bnode_t *bn, int indent)
{
	struct json_object_iterator it;
	struct json_object_iterator it_end;
	struct json_object* obj;
	int i;

	for (i=0; i<indent; i++)
		fprintf(stderr, ".");

	fprintf(stderr, "<%s", bn->desc);

	if(bn->attr)
	{
		obj = bn->attr;
		it = json_object_iter_begin(obj);
		it_end = json_object_iter_end(obj);

		while (!json_object_iter_equal(&it, &it_end))
		{
			fprintf(stderr, ",%s:%s",
					json_object_iter_peek_name(&it),
					json_object_get_string(
						json_object_iter_peek_value(&it)));

			json_object_iter_next(&it);
		}
	}

	fprintf(stderr, "|len=%d,type=%s>\n", bn->len,
		bnode_type_str[bn->type]);

	if(bn->type == BNODE_LIST)
	{
		for(i=0; i < bn->len; i++)
		{
			bnode_summary(bn->data.list[i], indent + 2);
		}
	}
	return 0;
}

int
bnode_print(bnode_t *bn, int indent)
{
	int i;
	char *pad = malloc(indent + 1);
	char *type_str = "unknown";
	for(i=0; i<indent; i++)
	{
		pad[i] = ' ';
	}
	pad[indent] = '\0';

	fprintf(stderr, "%sBNODE\n", pad);
	fprintf(stderr, "%s{\n", pad);

	fprintf(stderr, "%s  desc: %s\n", pad, bn->desc);


	type_str = bnode_type_str[bn->type];
	fprintf(stderr, "%s  type: %s\n", pad, type_str);

	/* Print attrs here */

	if(bn->attr)
		print_attr(bn, indent+2);

	switch(bn->type)
	{
		case BNODE_EMPTY:
			fprintf(stderr, "%s  content: empty\n", pad);
			break;
		case BNODE_STRING:
			fprintf(stderr, "%s  content: %s\n", pad, bn->data.str);
			break;
		case BNODE_LIST:
			fprintf(stderr, "%s  content\n", pad);
			fprintf(stderr, "%s  {\n", pad);
			for(i=0; i < bn->len; i++)
			{
				bnode_print(bn->data.list[i], indent+4);
			}
			break;
		case BNODE_BINARY:
			fprintf(stderr, "%s  content: binary(%d):\n", pad, bn->len);
#if (DEBUG >= LOG_LEVEL_DEBUG)
			hexdump(bn->data.bytes, bn->len);
#endif
			break;
		default:
			LOG_ERR("Unknown bnode type %d\n", bn->type);
			return -1;
	}

	fprintf(stderr, "%s}\n", pad);

	free(pad);

	return 0;
}

//int
//bnode_print_msg(msg_t *msg)
//{
//	bnode_t *bn = bnode_parse_msg(msg);
//
//	return bnode_print(bn, 0);
//}
//
//#include "test/msg.h"
//int
//main()
//{
//	msg_t *msg = malloc(sizeof(msg_t));
//	msg->cmd = msg2;
//	msg->len = msg2_len;
//
//	bnode_print_msg(msg);
//
//	return 0;
//}
