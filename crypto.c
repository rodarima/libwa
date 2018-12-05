#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "crypto.h"
#include "msg.h"
#include "buf.h"

#define DEBUG LOG_LEVEL_INFO
#define CLIENT_ID_BYTES 16

#define TEST_KEYS 0

#include "log.h"

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


#if (DEBUG >= LOG_LEVEL_DEBUG)
#define LOG_HEXDUMP(buf, len) hexdump(buf, len)
#define LOG_HEXDUMP_BUF(buf) buf_hexdump(buf)
#else
#define LOG_HEXDUMP(buf, len)
#define LOG_HEXDUMP_BUF(buf)
#endif

size_t
b64_decode_len(const char *str)
{
	size_t len, pad = 0;

	len = strlen(str);

	if (str[len-1] == '=') pad++;
	if (str[len-2] == '=') pad++;

	return (len * 3) / 4 - pad;
}

buf_t *
crypto_b64_decode(const char *str)
{
	BIO *bio, *b64;
	buf_t *buf;

	size_t dec_len, comp_len;

	comp_len = b64_decode_len(str);

	bio = BIO_new_mem_buf(str, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	// No b64 newlines.
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	buf = buf_init(comp_len);
	dec_len = BIO_read(bio, buf->ptr, strlen(str));
	assert(dec_len == comp_len);
	BIO_free_all(bio);

	return buf;
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

	c->client = NULL;

#if TEST_KEYS
	/* Set the key by hand, to ensure the same results as the tests */
	unsigned char *priv_key = (unsigned char *)" j\xfd.\xd1\x88!+\x17\xe8*\xfe\x81\xcf\x06\x0bL\xd4\x1a\x8a[\xf0\x19\xd9\x15v\xc1Z\x90\xd9R[";

	c->client = EVP_PKEY_new_raw_private_key(
			EVP_PKEY_X25519, NULL, priv_key, 32);

	LOG_DEBUG("Private key:\n");
	LOG_HEXDUMP(priv_key, 32);

	unsigned char *pub_key_buf;
	int len;

	len = EVP_PKEY_get1_tls_encodedpoint(c->client, &pub_key_buf);

	LOG_DEBUG("Public key:\n");
	LOG_HEXDUMP(pub_key_buf, len);

#else

	/* Generate private and public key */
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);

	if (!pctx)
		return NULL;

	if (EVP_PKEY_keygen_init(pctx) != 1)
		return NULL;

	if (EVP_PKEY_keygen(pctx, &c->client) != 1)
		return NULL;

	EVP_PKEY_CTX_free(pctx);
#endif


	return c;
}

char *
crypto_pubkey_to_b64(EVP_PKEY *p)
{
	unsigned char *pub_key_buf;
	int len;

	len = EVP_PKEY_get1_tls_encodedpoint(p, &pub_key_buf);

	return crypto_b64_encode((char *) pub_key_buf, len);
}

static buf_t *
derive_shared_key(EVP_PKEY *client, EVP_PKEY *peer)
{

	/* Generate shared secret */
	EVP_PKEY_CTX *ctx;
	size_t len;
	buf_t *shared_key;

	ctx = EVP_PKEY_CTX_new(client, NULL);

	EVP_PKEY_derive_init(ctx);
	EVP_PKEY_derive_set_peer(ctx, peer);
	EVP_PKEY_derive(ctx, NULL, &len);

	shared_key = buf_init(len);

	EVP_PKEY_derive(ctx, shared_key->ptr, &len);

	LOG_DEBUG("Shared key:\n");
	LOG_HEXDUMP_BUF(shared_key);

	return shared_key;
}

buf_t *
expand_shared_key(buf_t *shared_key)
{
	size_t len = 80;
	buf_t *buf = buf_init(len);

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	EVP_PKEY_derive_init(pctx);
	EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
	/*EVP_PKEY_CTX_set1_hkdf_salt(pctx, "salt", 4);*/
	EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_key->ptr, shared_key->len);
	/*EVP_PKEY_CTX_add1_hkdf_info(pctx, "", 0);*/
	EVP_PKEY_derive(pctx, buf->ptr, &len);

	LOG_DEBUG("Expanded key:\n");
	LOG_HEXDUMP_BUF(buf);

	return buf;
}

int
verify_expanded_key(buf_t *secret, buf_t *expanded_key)
{
	void *key = &expanded_key->ptr[32];
	size_t enc_len = secret->len - 32;
	unsigned char *enc = malloc(enc_len);
	unsigned char *sum = malloc(32);
	unsigned char *md = malloc(32);
	unsigned int md_len = 32;
	int cmp;

	memcpy(enc, &secret->ptr[0], 32);
	memcpy(sum, &secret->ptr[32], 32);
	memcpy(&enc[32], &secret->ptr[64], enc_len - 32);

	HMAC(EVP_sha256(), key, 32, enc, enc_len, md, &md_len);

	LOG_DEBUG("Computed HMAC:\n");
	LOG_HEXDUMP(md, 32);
	LOG_DEBUG("Expected HMAC:\n");
	LOG_HEXDUMP(sum, 32);

	cmp = memcmp(md, sum, 32);

	free(enc);
	free(sum);
	free(md);

	return cmp;
}

buf_t *
decrypt_keys(const buf_t *secret, const buf_t *ekey)
{
	buf_t *decrypted;
	size_t enc_len, dec_len = 0, final_len = 0;
	unsigned char *enc, *dec;
	unsigned char key[32];
	unsigned char iv[16];

	enc_len = secret->len - 64;
	enc = malloc(enc_len);
	dec = malloc(enc_len + 32);

	memcpy(key, ekey->ptr, 32);
	memcpy(iv, ekey->ptr + 64, 16);

	memcpy(enc, secret->ptr + 64, enc_len);

	LOG_DEBUG("key:\n");
	LOG_HEXDUMP(key, 32);
	LOG_DEBUG("iv:\n");
	LOG_HEXDUMP(iv, 16);
	LOG_DEBUG("encrypted data:\n");
	LOG_HEXDUMP(enc, enc_len);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, dec, (int *)&dec_len, enc, enc_len);
	LOG_DEBUG("dec_len = %ld\n", dec_len);
	EVP_DecryptFinal_ex(ctx, dec + dec_len, (int *)&final_len);

	LOG_DEBUG("final_len = %ld\n", final_len);
	dec_len += final_len;

	LOG_DEBUG("dec_len = %ld, enc_len = %ld\n",
			dec_len, enc_len);

	LOG_DEBUG("Decrypted keys:\n");
	LOG_HEXDUMP(dec, dec_len);

	decrypted = buf_init(dec_len);
	memcpy(decrypted->ptr, dec, dec_len);

	free(dec);
	free(enc);

	return decrypted;
}

buf_t *
get_enc_key(buf_t *dec_keys)
{
	buf_t *enc_key = buf_init(32);

	memcpy(enc_key->ptr, dec_keys->ptr, 32);

	return enc_key;
}

buf_t *
get_mac_key(buf_t *dec_keys)
{
	buf_t *mac_key = buf_init(32);

	memcpy(mac_key->ptr, dec_keys->ptr + 32, 32);

	return mac_key;
}


int
crypto_update_secret(crypto_t *c, const char *b64_secret)
{
	buf_t *shared_key;
	buf_t *expanded_key;
	buf_t *dec_keys;
	buf_t *secret;
	buf_t *peer_pubkey;

	secret = crypto_b64_decode(b64_secret);

	assert(secret->len == 144);

	LOG_DEBUG("Secret:\n");
	LOG_HEXDUMP_BUF(secret);

	peer_pubkey = buf_init(32);
	memcpy(peer_pubkey->ptr, secret->ptr, 32);

	EVP_PKEY *peer_key;

	LOG_DEBUG("Peer public key:\n");
	LOG_HEXDUMP_BUF(peer_pubkey);

	peer_key = EVP_PKEY_new_raw_public_key(
			EVP_PKEY_X25519, NULL,
			peer_pubkey->ptr, peer_pubkey->len);

	buf_free(peer_pubkey);

	assert(peer_key);

	shared_key = derive_shared_key(c->client, peer_key);

	expanded_key = expand_shared_key(shared_key);

	if(verify_expanded_key(secret, expanded_key))
		return 1;

	dec_keys = decrypt_keys(secret, expanded_key);

	buf_free(secret);
	buf_free(shared_key);
	buf_free(expanded_key);

	c->enc_key = get_enc_key(dec_keys);
	c->mac_key = get_mac_key(dec_keys);

	/* XXX: Not used anymore? */
	buf_free(dec_keys);

	return 0;
}

msg_t *
crypto_decrypt_msg(crypto_t *c, msg_t *msg)
{
	/*unsigned char *hmac_sum = msg->cmd;*/
	unsigned char *iv = msg->cmd + 32;
	unsigned char *enc_msg = msg->cmd + 32 + 16;

	int enc_msg_len = msg->len - (32 + 16);
	int dec_msg_len = enc_msg_len + 32;
	int final_len = 0;
	unsigned char *dec_msg = malloc(dec_msg_len);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, c->enc_key->ptr, iv);
	EVP_DecryptUpdate(ctx, dec_msg, &dec_msg_len, enc_msg, enc_msg_len);
	EVP_DecryptFinal_ex(ctx, dec_msg + dec_msg_len, &final_len);
	dec_msg_len += final_len;

	LOG_DEBUG("MSG DECRYPTED:\n");
	LOG_HEXDUMP(dec_msg, dec_msg_len);
	/*
	 * TODO: Verify msg with HMAC
	 *
	 * LOG_DEBUG("HMAC sum\n");
	 * LOG_HEXDUMP((char *)hmac_sum, 32);
	*/

	msg_t *dmsg = malloc(sizeof(msg_t));
	dmsg->tag = strdup(msg->tag);
	dmsg->cmd = dec_msg;
	dmsg->len = dec_msg_len;

	return dmsg;
}


char *
crypto_generate_client_id()
{
	char buf[CLIENT_ID_BYTES], *client_id;
	if(RAND_bytes((unsigned char *)buf, CLIENT_ID_BYTES) <= 0)
	{
		return NULL;
	}

	client_id = crypto_b64_encode(buf, CLIENT_ID_BYTES);

	return client_id;
}

char *
crypto_get_pub_client(crypto_t *c)
{
	return crypto_pubkey_to_b64(c->client);
}
