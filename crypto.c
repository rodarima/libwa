#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>


int generate_keys(EVP_PKEY *pkey)
{
	/* Generate private and public key */
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);

	if (!pctx)
		return -1;

	if (EVP_PKEY_keygen_init(pctx) <= 0)
		return -1;

	if (EVP_PKEY_keygen(pctx, &pkey))
		return -1;

	EVP_PKEY_CTX_free(pctx);

	return 0;
}


