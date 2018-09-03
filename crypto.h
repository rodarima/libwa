#ifndef _CRYPTO_H_
#define _CRYPO_H_

#include <openssl/evp.h>

char* b64_encode(char* buf, size_t len);
int generate_keys(EVP_PKEY **pkey);
char *get_public_key(EVP_PKEY *pkey);

#endif
