#include <stdio.h>
#include "pmsg.pb-c.h"
#include "session.h"
#include "wa.h"
#include "l4.h"
#include "l3.h"

#define DEBUG LOG_LEVEL_INFO

#include "log.h"

#define LEN_MSG_KEY 10



static int
parse_priv_msg(wa_t *wa, Proto__WebMessageInfo *wmi)
{
	Proto__MessageKey *key;
	Proto__Message *msg;
	priv_msg_t *pm;
	user_t *remote;
	int ret;

	key = wmi->key;

	if(!key)
	{
		LOG_WARN("Received msg without key, ignoring\n");
		return -1;
	}

	remote = session_find_user(wa, key->remotejid);
	if(!remote)
	{
		if(wmi->message && wmi->message->conversation)
		{
			LOG_WARN("Remote jid not found: %s said : %s\n",
				key->remotejid, wmi->message->conversation);
		}
		else
		{
			LOG_WARN("Remote jid not found: %s\n", key->remotejid);
		}

		if(wmi->has_status)
		{
			LOG_WARN("Status = %d\n", wmi->status);
		}
		return -1;
	}

	msg = wmi->message;

	if(!msg)
	{
		LOG_WARN("%s: message is NULL\n", key->remotejid);
		return -1;
	}

	pm = malloc(sizeof(priv_msg_t));
	assert(pm);

	if(!msg->conversation)
	{
		LOG_WARN("%s: message text is NULL\n", key->remotejid);
		return -1;
	}

	/* Copy the text, as the whole wmi will be destroyed */
	pm->text = strdup(msg->conversation);

	if(key->has_fromme && key->fromme)
	{
		pm->from = wa->me;
		pm->to = remote;
		pm->from_me = 1;
	}
	else
	{
		pm->from = remote;
		pm->to = wa->me;
		pm->from_me = 0;
		LOG_INFO("Priv msg received from %s : %s\n",
				pm->from->name, pm->text);
	}

	ret = session_recv_priv_msg(wa, pm);

	if((ret == 0) && (wa->state == WA_STATE_READY))
	{
		/* Confirm reception, but only after READY state */
		l3_send_seen(wa, key->remotejid, key->id);
	}

	/* Don't free after the callback, in order to use the data after the
	 * return */
	//free(pm);

	return ret;
}

static int
parse_group_msg(wa_t *wa, Proto__WebMessageInfo *wmi)
{
	LOG_INFO("Group msg not implemented: %p\n", wmi);
	return 0;
}

int
l4_recv_msg(wa_t *wa, unsigned char *buf, size_t len)
{
	Proto__WebMessageInfo *wmi;
	int ret;

	wmi = proto__web_message_info__unpack(NULL, len, buf);

	assert(wmi);

	if(!wmi->key)
	{
		LOG_WARN("Required field 'key' missing\n");
		ret = -1;
	}
	else
	{
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
	}

	proto__web_message_info__free_unpacked(wmi, NULL);

	return ret;
}

char *
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

int
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

	key->remotejid = pm->to->jid;

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

	l3_send_relay_msg(wa, buf, key->id);

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
	pm->from = wa->me;
	pm->to = to;
	pm->text = text;

	send_priv_msg(wa, pm);

	return 0;
}


