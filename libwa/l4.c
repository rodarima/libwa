#include <stdio.h>
#include "pmsg.pb-c.h"
#include "session.h"
#include "wa.h"
#include "l4.h"
#include "l3.h"
#include "chat.h"
#include "monitor.h"
#include "wire.h"

#define DEBUG LOG_LEVEL_DEBUG

#include "log.h"

#define LEN_MSG_KEY 10




static int
l4_send_seen(wa_t *wa, char *jid, char *id)
{
	int ret;
	dg_t *dg;

	dg = dg_cmd(L4, L3, "send_seen");
	dg_meta_set(dg, "jid", jid);
	dg_meta_set(dg, "id", id);

	/* Blocking send */
	ret = wire_handle(wa, dg);

	dg_free(dg);

	return ret;
}

static char *
random_key()
{
	char *l = "0123456789ABCDEF";
	buf_t *buf;
	int i, j = 0, b;
	char *key = malloc(LEN_MSG_KEY*2 + 1);

	buf = crypto_random_buf(LEN_MSG_KEY);

	for(i=0; i < LEN_MSG_KEY; i++)
	{
		/* Note the nibbles are swapped here, but we don't care */
		b = buf->ptr[i];
		key[j++] = l[b & 0x0F];
		b = b >> 4;
		key[j++] = l[b & 0x0F];
	}

	key[j] = '\0';

	buf_free(buf);

	/* The first part is always the same. Note we don't truncate the key */
	char *head = "3EB0";
	memcpy(key, head, strlen(head));

	return key;
}

static int
send_priv_msg(wa_t *wa, priv_msg_t *pm)
{

	Proto__WebMessageInfo *wmi;
	Proto__MessageKey *key;
	Proto__Message *msg;
	struct timespec tp;
	buf_t *buf;
	size_t len;

	clock_gettime(CLOCK_REALTIME, &tp);

	msg = calloc(1, sizeof(*msg));
	key = calloc(1, sizeof(*key));
	wmi = calloc(1, sizeof(*wmi));

	proto__web_message_info__init(wmi);
	proto__message_key__init(key);
	proto__message__init(msg);

	msg->conversation = pm->text;

	key->has_fromme = 1;
	key->fromme = 1;

	key->remotejid = pm->jid;

	key->id = random_key();
	LOG_DEBUG("Random key is set to: %s\n", key->id);

	wmi->has_messagetimestamp = 1;
	wmi->messagetimestamp = tp.tv_sec;

	wmi->has_status = 1;
	wmi->status = PROTO__WEB_MESSAGE_INFO__STATUS__PENDING;

	wmi->message = msg;
	wmi->key = key;

	len = proto__web_message_info__get_packed_size(wmi);

	buf = buf_init(len);

	proto__web_message_info__pack(wmi, buf->ptr);

	dg_t *dg = dg_cmd(L4, L3, "send_relay_message");
	dg_meta_set(dg, "tag", key->id);
	dg->data = buf;

	wire_handle(wa, dg);

	free(key->id);

	free(msg);
	free(key);
	free(wmi);


	buf_free(buf);

	return 0;
}

int
l4_send_priv_msg(wa_t *wa, char *to_jid, char *text)
{
	priv_msg_t *pm;
	user_t *to;

	to = session_find_user(wa, to_jid);

	if(!to)
	{
		LOG_ERR("Can't find user %s, aborting\n", to_jid);
		return -1;
	}

	pm = malloc(sizeof(priv_msg_t));
	pm->user = to;
	pm->jid = to_jid;
	pm->text = text;
	/* TODO: Timestamp */

	send_priv_msg(wa, pm);

	return 0;
}

static int
parse_group_msg(wa_t *wa, Proto__WebMessageInfo *wmi)
{
	LOG_INFO("Group msg not implemented: %p\n", wmi);
	return 0;
}

static int
parse_priv_msg(wa_t *wa, Proto__WebMessageInfo *wmi)
{
	Proto__MessageKey *key;
	Proto__Message *msg;
	priv_msg_t *pm;
	int ret;

	key = wmi->key;

	if(!key)
	{
		LOG_WARN("Received msg without key, ignoring\n");
		return -1;
	}

	LOG_DEBUG("Received msg with key:%s\n", key->id);

	msg = wmi->message;

	if(!msg)
	{
		LOG_WARN("%s: message is NULL\n", key->remotejid);
		return -1;
	}

	if(!msg->conversation)
	{
		LOG_WARN("%s: message text is NULL\n", key->remotejid);
		return -1;
	}

	if(wmi->has_status)
	{
		LOG_DEBUG("Received msg with status = %d\n", wmi->status);
	}


	pm = calloc(1, sizeof(priv_msg_t));
	assert(pm);

	pm->timestamp = wmi->messagetimestamp;

	/* Copy the text, as the whole wmi will be destroyed */
	pm->text = strdup(msg->conversation);

	pm->jid = strdup(key->remotejid);
	pm->msg_id = strdup(key->id);
	/* Contacts may not be ready */
	//pm->user = remote;

	if(key->has_fromme && key->fromme)
		pm->from_me = 1;

	ret = chat_recv_priv_msg(wa, pm);

	/* TODO: Let the user decide if ack must be sent */
	if((ret == 0) && (wa->state == WA_STATE_READY))
	{
		/* Confirm reception, but only after READY state */
		l4_send_seen(wa, key->remotejid, key->id);
	}

	/* Don't free after the callback, in order to use the data after the
	 * return */
	//free(pm);

	return ret;
}

static int
l4_recv_message(wa_t *wa, dg_t *dg)
{
	Proto__WebMessageInfo *wmi;
	int ret, last;

	if(dg_meta_get_int(dg, "last", &last))
	{
		LOG_ERR("Missing 'last' key in metadata\n");
		return -1;
	}

	wmi = proto__web_message_info__unpack(
			NULL, dg->data->len, dg->data->ptr);

	if(!wmi)
	{
		LOG_ERR("Protobuf unpack failed\n");
		return -1;
	}

	if(!wmi->key)
	{
		LOG_WARN("Required field 'key' missing\n");
		ret = -1;
		goto err;
	}

	/* If there is any participant, the message comes from a group */
	if(wmi->key->participant)
	{
		ret = parse_group_msg(wa, wmi);
	}
	else
	{
		/* Otherwise is a private msg */
		ret = parse_priv_msg(wa, wmi);
	}

	if(last && wa->state >= WA_STATE_CONTACTS_RECEIVED)
	{
		LOG_DEBUG("wa->state = %d, flushing chats\n", wa->state);
		chat_flush(wa);
	}

err:
	proto__web_message_info__free_unpacked(wmi, NULL);

	return ret;
}


int
l4_recv(wa_t *wa, dg_t *dg)
{
	char *cmd;

	cmd = dg_meta_get(dg, "cmd");

	if(!cmd)
	{
		LOG_ERR("Malformed internal datagram without cmd\n");
		return -1;
	}

	if(strcmp(cmd, "recv_message") == 0)
		return l4_recv_message(wa, dg);

	LOG_ERR("Unknown cmd in internal datagram: %s\n", cmd);
	return -1;
}
