#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/evp.h>
#include "msg.h"

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

	/* Both keys are 32 bytes long */
	unsigned char *enc_key;
	unsigned char *mac_key;
} crypto_t;


crypto_t *
crypto_init();

char *
crypto_b64_encode(char* buf, size_t len);

int
crypto_b64_decode(const char *str, char **ptrbuf, size_t *ptrlen);

int
crypto_update_secret(crypto_t *c, const char *b64_secret);

msg_t *
crypto_decrypt_msg(crypto_t *c, msg_t *msg);

char *
crypto_get_public_key(crypto_t *c);

void
hexdump(char *buf, size_t len);

#endif
