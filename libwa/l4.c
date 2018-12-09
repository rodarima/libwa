#include <stdio.h>
#include "pmsg.pb-c.h"
#include "session.h"
#include "wa.h"
#include "l4.h"

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


