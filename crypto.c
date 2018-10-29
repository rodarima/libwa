#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>

#include "crypto.h"

#define DEBUG 1

/* WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 * OpenSSL is a mess. I would not consider it secure by the simple observation
 * that is extremely easy to make a mistake. Look at the complexity of base64
 * decoding, for example.
 *
 * It is here only while I look for an alternative that can be used in different
 * architectures.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING */

void
hexdump(char *buf, size_t len)
{
	int i;
	for(i=0; i<len; i++)
	{
		printf("%02X ", (unsigned char) buf[i]);

		if((i % 16) == 15)
			printf("\n");

		if((i % 16) == 7)
			printf(" ");
	}
	printf("\n");
}

size_t
b64_decode_len(const char *str)
{
	size_t len, pad = 0;

	len = strlen(str);

	if (str[len-1] == '=') pad++;
	if (str[len-2] == '=') pad++;

	return (len * 3) / 4 - pad;
}

int
crypto_b64_decode(const char *str, char **ptrbuf, size_t *ptrlen)
{
	BIO *bio, *b64;

	size_t len = b64_decode_len(str);
	char *buf = malloc(len);
	assert(buf);

	bio = BIO_new_mem_buf(str, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	// No b64 newlines.
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	*ptrlen = BIO_read(bio, buf, strlen(str));
	assert(*ptrlen == len);
	BIO_free_all(bio);

	*ptrbuf = (void *) buf;

	return 0;
}

char *
crypto_b64_encode(char* buf, size_t len)
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

/* More info: https://www.openssl.org/docs/manmaster/man7/Ed25519.html
 * And see EVP_PKEY_NEW(3) */

crypto_t *
crypto_init()
{
	crypto_t *c = malloc(sizeof(crypto_t));
	assert(c);

	c->peer_key = NULL;
	c->client_key = NULL;

#if DEBUG
	/* Set the key by hand, to ensure the same results as the tests */
	char *priv_key = " j\xfd.\xd1\x88!+\x17\xe8*\xfe\x81\xcf\x06\x0bL\xd4\x1a\x8a[\xf0\x19\xd9\x15v\xc1Z\x90\xd9R[";

	c->client_key = EVP_PKEY_new_raw_private_key(
			EVP_PKEY_X25519, NULL, (unsigned char *)priv_key, 32);

	printf("Private key:\n");
	hexdump(priv_key, 32);

	char *pub_key_buf;
	int len;

	len = EVP_PKEY_get1_tls_encodedpoint(c->client_key, (unsigned char **)&pub_key_buf);

	printf("Public key:\n");
	hexdump(pub_key_buf, len);

#else

	/* Generate private and public key */
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);

	if (!pctx)
		return NULL;

	if (EVP_PKEY_keygen_init(pctx) != 1)
		return NULL;

	if (EVP_PKEY_keygen(pctx, &c->client_key) != 1)
		return NULL;

	EVP_PKEY_CTX_free(pctx);
#endif


	return c;
}

char *
get_public_key(EVP_PKEY *pkey)
{
	unsigned char *pub_key_buf;
	int len;

	len = EVP_PKEY_get1_tls_encodedpoint(pkey, &pub_key_buf);

	if (len != 32)
		return NULL;

	return crypto_b64_encode((char *) pub_key_buf, len);
}

static int
derive_shared_key(crypto_t *c, EVP_PKEY *peer_key)
{

	/* Generate shared secret */
	EVP_PKEY_CTX *ctx;
	unsigned char *skey;
	size_t skeylen;

	ctx = EVP_PKEY_CTX_new(c->client_key, NULL);

	EVP_PKEY_derive_init(ctx);
	EVP_PKEY_derive_set_peer(ctx, peer_key);
	EVP_PKEY_derive(ctx, NULL, &skeylen);
	skey = malloc(skeylen);
	EVP_PKEY_derive(ctx, skey, &skeylen);

	c->shared_key = (char *) skey;
	c->shared_key_len = skeylen;

	printf("Shared key:\n");
	hexdump(c->shared_key, c->shared_key_len);

	return 0;
}

int
expand_shared_key(crypto_t *c)
{
	size_t outlen = 80;
	char *out = malloc(outlen);

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	EVP_PKEY_derive_init(pctx);
	EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
	/*EVP_PKEY_CTX_set1_hkdf_salt(pctx, "salt", 4);*/
	EVP_PKEY_CTX_set1_hkdf_key(pctx, c->shared_key, c->shared_key_len);
	/*EVP_PKEY_CTX_add1_hkdf_info(pctx, "", 0);*/
	EVP_PKEY_derive(pctx, (unsigned char *)out, &outlen);

	c->expanded_key = out;
	c->expanded_key_len = outlen;

	printf("Expanded key:\n");
	hexdump(out, outlen);
	return 0;
}

int
verify_expanded_key(crypto_t *c)
{
	void *key = &c->expanded_key[32];
	size_t enc_len = c->secret_len - 32;
	char *enc = malloc(enc_len);
	char *sum = malloc(32);
	char *md = malloc(32);
	unsigned int md_len = 32;
	int cmp;

	memcpy(enc, &c->secret[0], 32);
	memcpy(sum, &c->secret[32], 32);
	memcpy(&enc[32], &c->secret[64], enc_len - 32);

	HMAC(EVP_sha256(), key, 32,
			(unsigned char *)enc, enc_len,
			(unsigned char *)md, &md_len);

	printf("Computed HMAC:\n");
	hexdump(md, 32);
	printf("Expected HMAC:\n");
	hexdump(sum, 32);

	cmp = memcmp(md, sum, 32);

	free(enc);
	free(sum);
	free(md);

	return cmp;
}

int
update_encryption_keys(crypto_t *c)
{
	//EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	size_t expanded_len = c->expanded_key_len - 64;
	size_t secret_len = c->expanded_key_len - 64;
	size_t enc_len = expanded_len + secret_len;

	char *enc = malloc(enc_len);
	char key[32];
	char iv[16];

	memcpy(enc, &c->expanded_key[64], expanded_len);
	memcpy(&enc[expanded_len], &c->secret[64], secret_len);

	memcpy(key, c->expanded_key, 32);
	memcpy(iv, enc, 16);

	// TODO: Decrypt the keys stored in enc
	//EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	//EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen);
	//EVP_CipherFinal_ex(ctx, outbuf, &outlen);

	return 0;
}

int
crypto_update_secret(crypto_t *c, const char *b64_secret)
{
	crypto_b64_decode(b64_secret, &c->secret, &c->secret_len);

	assert(c->secret_len == 144);

	printf("Secret:\n");
	hexdump(c->secret, c->secret_len);

	EVP_PKEY *peer_key;

	printf("Peer public key:\n");
	hexdump(c->secret, 32);

	peer_key = EVP_PKEY_new_raw_public_key(
			EVP_PKEY_X25519, NULL, (unsigned char *)c->secret, 32);

	derive_shared_key(c, peer_key);

	expand_shared_key(c);

	if(!verify_expanded_key(c))
		return 1;

	update_encryption_keys(c);

	return 0;
}

/*
int
main()
{
	char *buf;
	size_t len;

	crypto_b64_decode("Y2FjYWh1ZXRpbGxvAA==", &buf, &len);

	printf("%s\n", buf);
	hexdump(buf, len);
}
*/

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
