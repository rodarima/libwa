#include "wa.h"
#include "crypto.h"

#include "l2.h"
#include "wire.h"

#define DEBUG LOG_LEVEL_ERR
#include "log.h"

int
l2_recv(wa_t *wa, dg_t *dg)
{
	int ret;
	buf_t *buf, *tmp;

	/* It seems the only kind of messages inside a encrypted binary message
	 * are bnode messages */

	/* FIXME: This ugly hack avoids double serialization here... */
	tmp = dg->data;
	dg->dst = L3;
	dg->src = L2;

	if(dg->data)
	{
		buf = crypto_decrypt_buf(wa->c, dg->data);

		if(!buf)
		{
			LOG_ERR("Decryption failed\n");
			return 1;
		}

		dg->data = buf;
	}

	ret = wire_handle(wa, dg);

	if(dg->data)
		buf_free(dg->data);

	/* Leave the original data */
	dg->data = tmp;

	return ret;
}

int
l2_send(wa_t *wa, dg_t *dg)
{
	int ret;
	buf_t *out, *tmp;

	/* FIXME: This ugly hack avoids double serialization here... */
	tmp = dg->data;
	dg->dst = L1;
	dg->src = L2;

	if(dg->data)
	{
		out = crypto_encrypt_buf(wa->c, dg->data);

		if(!out)
		{
			LOG_ERR("Encryption failed\n");
			return 1;
		}

		dg->data = out;
	}

	ret = wire_handle(wa, dg);

	if(dg->data)
		buf_free(dg->data);

	/* Leave the original buf */
	dg->data = tmp;

	return ret;
}
