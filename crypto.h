#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/evp.h>

typedef struct {
	EVP_PKEY *client_key;
	EVP_PKEY *peer_key;

	/* The secret contains important information */
	char *secret;
	size_t secret_len;

	char *shared_key;
	size_t shared_key_len;

	char *expanded_key;
	size_t expanded_key_len;
} crypto_t;


crypto_t *
crypto_init();

char *
crypto_b64_encode(char* buf, size_t len);

int
crypto_b64_decode(const char *str, char **ptrbuf, size_t *ptrlen);

int
crypto_update_secret(crypto_t *c, const char *b64_secret);

#endif
