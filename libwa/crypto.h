#pragma once

#include <json-c/json.h>
#include <openssl/evp.h>

#include "buf.h"
#include "msg.h"

typedef struct {
	/* The keys derived from the secret */
	buf_t *enc_key;
	buf_t *mac_key;

	/* Own key pair */
	EVP_PKEY *client;
} crypto_t;

crypto_t *
crypto_init();

void
crypto_free(crypto_t *c);

char *
crypto_b64_encode(unsigned char* buf, size_t len);

buf_t *
crypto_b64_decode(const char *str);

char *
crypto_pubkey_to_b64(EVP_PKEY *p);

int
crypto_update_secret(crypto_t *c, const char *b64_secret);

msg_t *
crypto_decrypt_msg(crypto_t *c, msg_t *msg);

char *
crypto_generate_client_id();

char *
crypto_get_pub_client(crypto_t *c);

json_object *
crypto_save(crypto_t *c);

int
crypto_restore(crypto_t *c, json_object *root);

char *
crypto_solve_challenge(crypto_t *c, const char *challenge_b64);

buf_t *
crypto_encrypt_buf(crypto_t *c, buf_t *in);

buf_t *
crypto_decrypt_buf(crypto_t *c, buf_t *in);

buf_t *
crypto_random_buf(size_t n);
