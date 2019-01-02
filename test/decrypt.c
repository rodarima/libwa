#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <json-c/json.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


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
	unsigned char *ptr;
	size_t len, remainder;
	bnode_t *bn;
	int ret = 0;

	c = crypto_init();

	root = json_object_from_file("crypto-session.json");

	crypto_restore(c, root);

	fd = open(fpath, O_RDONLY);
	fstat(fd, &sb);

	mem = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	//ptr = (void*)mem;

	fprintf(stderr, "file size = %ld\n", sb.st_size);

	ptr = memchr(mem, ',', sb.st_size);

	if(!ptr)
	{
		ret = 1;
		goto out;
	}

	ptr++;

	len = sb.st_size - (ptr - (unsigned char *)mem);

	remainder = len % 16;

	fprintf(stderr, "len = %ld, remainder = %ld\n", len, remainder);

	if(remainder != 0)
	{
		fprintf(stderr, "Skipping %ld bytes of header\n", remainder);
		fprintf(stderr, "metric = %d, flags = 0x%02x\n", ptr[0], ptr[1]);
		len -= remainder;
		ptr += remainder;
	}

	buf.ptr = (unsigned char*) ptr;
	buf.len = len;

	fprintf(stderr, "In:\n");
	buf_hexdump(&buf);

	out = crypto_decrypt_buf(c, &buf);

	fprintf(stderr, "Out:\n");
	buf_hexdump(out);

	bn = bnode_from_buf(out);

	bnode_print(bn, 0);

	buf_free(out);

out:

	close(fd);

	return ret;
}

int
main(int argc, char *argv[])
{
	char *file;

	file = argv[1];

	return decrypt(file);
}
