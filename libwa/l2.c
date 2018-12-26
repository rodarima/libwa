#include "wa.h"
#include "msg.h"
#include "crypto.h"

#include "l1.h"
#include "l2.h"
#include "l3.h"

#define DEBUG LOG_LEVEL_ERR
#include "log.h"

int
l2_recv_msg(wa_t *wa, msg_t *msg_l1)
{
	msg_t *msg_l2;
	int ret;

	/* It seems the only kind of messages inside a encrypted binary message
	 * are bnode messages */

	msg_l2 = crypto_decrypt_msg(wa->c, msg_l1);

	ret = l3_recv_msg(wa, msg_l2);
	free(msg_l2->tag);
	free(msg_l2->cmd);
	free(msg_l2);

	return ret;
}

int
l2_send_buf(wa_t *wa, buf_t *in, char *tag, int metric, int flags)
{
	int ret = 0;
	buf_t *out;

	out = crypto_encrypt_buf(wa->c, in);

	ret = l1_send_buf(wa, out, tag, metric, flags);

	buf_free(out);

	return ret;
}

int
l2_send_plain(wa_t *wa, buf_t *in, char *tag, int metric, int flags)
{
	/* Dummy function */
	return l1_send_buf(wa, in, tag, metric, flags);
}
