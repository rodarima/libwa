#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <json-c/json.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "bnode.h"
#include "crypto.h"
#include "buf.h"

#define DEBUG LOG_LEVEL_INFO
#include "log.h"

int
decrypt(char *fpath)
{
	crypto_t *c;
	json_object *root;
	const char *mem;
	int fd;
	struct stat sb;
	buf_t buf, *out;
	void *ptr;
	size_t len;
	bnode_t *bn;

	c = crypto_init();

	root = json_object_from_file("crypto-session.json");

	crypto_restore(c, root);

	fd = open(fpath, O_RDONLY);
	fstat(fd, &sb);

	mem = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	ptr = (void*)mem;
	//ptr = memchr(mem, ',', sb.st_size);

	//if(!ptr)
	//	return 1;

	//ptr++;

	len = sb.st_size - (((void*) mem) - ptr);

	buf.ptr = (unsigned char*) ptr;
	buf.len = len;

	printf("In:\n");
	buf_hexdump(&buf);

	out = crypto_decrypt_buf(c, &buf);

	printf("Out:\n");
	buf_hexdump(out);

	bn = bnode_from_buf(out);

	bnode_print(bn, 0);

	buf_free(out);

	return 0;
}

int
main(int argc, char *argv[])
{
	char *file;

	file = argv[1];

	return decrypt(file);
}
