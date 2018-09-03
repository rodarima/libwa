#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

char* b64_encode(char* buf, size_t len)
{
	BIO *b64, *mem;
	BUF_MEM *bptr;
	char *outbuf;

	b64 = BIO_new(BIO_f_base64());
	mem = BIO_new(BIO_s_mem());

	// No b64 newlines.
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	b64 = BIO_push(b64, mem);

	BIO_write(b64, buf, len);
	BIO_flush(b64);

	BIO_get_mem_ptr(b64, &bptr);


	outbuf = malloc(bptr->length + 1);
	memcpy(outbuf, bptr->data, bptr->length);
	outbuf[bptr->length] = '\0';

	//BIO_set_close(b64, BIO_NOCLOSE);
	BIO_free_all(b64);


	return outbuf;
}

int generate_keys(EVP_PKEY **pkey)
{
	/* Generate private and public key */
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);

	if (!pctx)
		return -1;

	if (EVP_PKEY_keygen_init(pctx) != 1)
		return -1;

	if (EVP_PKEY_keygen(pctx, pkey) != 1)
		return -1;

	EVP_PKEY_CTX_free(pctx);

	return 0;
}

char *get_public_key(EVP_PKEY *pkey)
{
	unsigned char *pub_key_buf;
	int len;

	len = EVP_PKEY_get1_tls_encodedpoint(pkey, &pub_key_buf);

	if (len != 32)
		return NULL;

	return b64_encode(pub_key_buf, len);
}

/*
int main()
{
	EVP_PKEY *pkey = NULL;
	if(generate_keys(&pkey))
		return 1;

	EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);

	unsigned char *pub_key_buf;
	EVP_PKEY_get1_tls_encodedpoint(pkey, &pub_key_buf);

	int i;
	for(i=0; i<32; i++)
		printf("%02X ", pub_key_buf[i]);
	printf("\n");

	printf("%s\n", b64_encode(pub_key_buf, 32));

	return 0;
}
*/
