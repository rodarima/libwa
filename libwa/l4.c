#include <stdio.h>
#include "pmsg.pb-c.h"
#include "session.h"
#include "wa.h"
#include "l4.h"
#include "l3.h"

#define DEBUG LOG_LEVEL_ERR

#include "log.h"

static int
parse_priv_msg(wa_t *wa, Proto__WebMessageInfo *wmi)
{
	Proto__MessageKey *key;
	Proto__Message *msg;
	priv_msg_t *pm;
	user_t *remote;
	int ret;

	key = wmi->key;
	assert(key);

	remote = session_find_user(wa, key->remotejid);
	if(!remote)
	{
		LOG_WARN("Remote jid not found: %s\n", key->remotejid);
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

	pm->text = msg->conversation;

	assert(key->has_fromme);

	if(key->fromme)
	{
		pm->from = wa->me;
		pm->to = remote;
	}
	else
	{
		pm->from = remote;
		pm->to = wa->me;
		LOG_INFO("Priv msg received from %s : %s\n",
				pm->from->name, pm->text);
	}

	ret = session_recv_priv_msg(wa, pm);

	free(pm);

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

	/* TODO: Set real random key */
	key->id = "3EB02E178F06CD180E80";

	wmi->has_messagetimestamp = 1;
	wmi->messagetimestamp = tp.tv_sec;

	wmi->has_status = 1;
	wmi->status = PROTO__WEB_MESSAGE_INFO__STATUS__PENDING;

	wmi->message = msg;
	wmi->key = key;

	len = proto__web_message_info__get_packed_size(wmi);

	buf = buf_init(len);

	proto__web_message_info__pack(wmi, buf->ptr);

	l3_send_relay(wa, buf);

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
		return -1;

	pm = malloc(sizeof(priv_msg_t));
	pm->from = wa->me;
	pm->to = to;
	pm->text = text;

	send_priv_msg(wa, pm);

	return 0;
}

