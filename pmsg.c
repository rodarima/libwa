#include <stdio.h>
#include "pmsg.pb-c.h"
#include "session.h"

#define DEBUG 1

#include "log.h"

int
parse_priv_msg(session_t *s, Proto__WebMessageInfo *wmi)
{
	Proto__MessageKey *key;
	Proto__Message *msg;
	priv_msg_t *pm;
	user_t *remote;

	pm = malloc(sizeof(priv_msg_t));
	assert(pm);

	key = wmi->key;
	assert(key);

	remote = session_find_user(s, key->remotejid);
	if(!remote)
	{
		LOG_ERR("Remote jid not found: %s\n", key->remotejid);
		return -1;
	}

	msg = wmi->message;

	if(!msg)
	{
		LOG_WARN("%s: message is NULL\n", key->remotejid);
		return -1;
	}

	pm->text = msg->conversation;

	assert(key->has_fromme);

	if(key->fromme)
	{
		pm->from = s->me;
		pm->to = remote;
	}
	else
	{
		pm->from = remote;
		pm->to = s->me;
		LOG_INFO("Priv msg received from %s : %s\n",
				pm->from->name, pm->text);
	}

	return session_recv_priv_msg(s, pm);
}

int
parse_group_msg(session_t *s, Proto__WebMessageInfo *wmi)
{
	LOG_INFO("Group msg not implemented: %p\n", wmi);
	return 0;
}

int
pmsg_parse_message(session_t *s, char *buf, size_t len)
{
	Proto__WebMessageInfo *wmi;
	int ret;

	wmi = proto__web_message_info__unpack(
			NULL, len, (unsigned char *) buf);

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
			ret = parse_group_msg(s, wmi);
		}
		else
		{
			/* Otherwise is a private msg */
			ret = parse_priv_msg(s, wmi);
		}
	}

	proto__web_message_info__free_unpacked(wmi, NULL);

	return ret;
}
