#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <ctype.h>

#include "crypto.h"
#include "msg.h"


//#define DEBUG 1

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
	int i,j;
	for(i=0; i< 1 + (len-1)/16; i++)
	{
		for(j=0; j<16; j++)
		{
			int p = i*16 + j;
			if(p < len)
				printf("%02X ", (unsigned char) buf[p]);
			else
				printf("   ");

			if(j == 7)
				printf(" ");
		}
		printf("  ");
		for(j=0; j<16; j++)
		{
			int p = i*16 + j;
			if((p < len) && (isprint(buf[p])))
				printf("%c", buf[p]);
			else
				printf(".");
		}
		printf("\n");
	}
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
crypto_get_public_key(crypto_t *c)
{
	unsigned char *pub_key_buf;
	int len;

	len = EVP_PKEY_get1_tls_encodedpoint(c->client_key, &pub_key_buf);

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

#if DEBUG
	printf("Shared key:\n");
	hexdump(c->shared_key, c->shared_key_len);
#endif

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

#if DEBUG
	printf("Expanded key:\n");
	hexdump(out, outlen);
#endif

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

#if DEBUG
	printf("Computed HMAC:\n");
	hexdump(md, 32);
	printf("Expected HMAC:\n");
	hexdump(sum, 32);
#endif
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
	size_t enc_len = c->secret_len - 64;

	unsigned char *enc = malloc(enc_len);
	unsigned char *dec = malloc(enc_len + 32);
	size_t dec_len = 0, final_len = 0;
	unsigned char key[32];
	unsigned char iv[16];

	memcpy(key, c->expanded_key, 32);
	memcpy(iv, c->expanded_key + 64, 16);

	memcpy(enc, c->secret + 64, enc_len);

#if DEBUG
	printf("key:\n");
	hexdump((char *)key, 32);
	printf("iv:\n");
	hexdump((char *)iv, 16);
	printf("encrypted data:\n");
	hexdump((char*)enc, enc_len);
#endif

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, dec, (int *)&dec_len, enc, enc_len);
	printf("dec_len = %ld\n", dec_len);
	EVP_DecryptFinal_ex(ctx, dec + dec_len, (int *)&final_len);

	printf("final_len = %ld\n", final_len);
	dec_len += final_len;

#if DEBUG
	printf("dec_len = %ld, enc_len = %ld\n",
			dec_len, enc_len);

	printf("Decrypted keys:\n");
	hexdump((char *) dec, dec_len);
#endif
	char *enc_key = malloc(32);
	char *mac_key = malloc(32);

	memcpy(enc_key, dec, 32);
	memcpy(mac_key, dec + 32, 32);

	printf("enc_key:\n");
	hexdump(enc_key, 32);
	printf("mac_key:\n");
	hexdump(mac_key, 32);

	c->enc_key = (unsigned char *) enc_key;
	c->mac_key = (unsigned char *) mac_key;

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

	if(verify_expanded_key(c))
		return 1;

	update_encryption_keys(c);

	return 0;
}

msg_t *
crypto_decrypt_msg(crypto_t *c, msg_t *msg)
{
	unsigned char *hmac_sum = msg->cmd;
	unsigned char *iv = msg->cmd + 32;
	unsigned char *enc_msg = msg->cmd + 32 + 16;

	int enc_msg_len = msg->len - (32 + 16);
	int dec_msg_len = enc_msg_len + 32;
	int final_len = 0;
	unsigned char *dec_msg = malloc(dec_msg_len);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, c->enc_key, iv);
	EVP_DecryptUpdate(ctx, dec_msg, &dec_msg_len, enc_msg, enc_msg_len);
	EVP_DecryptFinal_ex(ctx, dec_msg + dec_msg_len, &final_len);
	dec_msg_len += final_len;

	printf("MSG DECRYPTED:\n");
	hexdump((char *)dec_msg, dec_msg_len);
	printf("HMAC sum\n");
	hexdump((char *)hmac_sum, 32);

	msg_t *dmsg = malloc(sizeof(msg_t));
	dmsg->tag = strdup(msg->tag);
	dmsg->cmd = dec_msg;
	dmsg->len = dec_msg_len;

	return dmsg;
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
