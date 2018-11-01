#include <stdio.h>
#include "pmsg.pb-c.h"
#include "log.h"

int
pmsg_unpack(char *buf, size_t len)
{
	Proto__WebMessageInfo *wmi;
	Proto__MessageKey *key;
	Proto__Message *msg;
	char *conv, *remotejid;

	wmi = proto__web_message_info__unpack(
			NULL, len, (unsigned char *) buf);

	assert(wmi);

	key = wmi->key;

	if(!key)
	{
		LOG_WARN("Required field 'key' missing\n");
		return -1;
	}

	if(key->remotejid)
		remotejid = key->remotejid;
	else
		remotejid = "<UNKNOWN>";

	msg = wmi->message;

	if(!msg)
	{
		LOG_WARN("%s: message is NULL\n", remotejid);
		return -1;
	}

	conv = msg->conversation;

	if(!conv)
	{
		conv = "<EMPTY>";
	}

	printf("%s: %s\n", remotejid, conv);

	proto__web_message_info__free_unpacked(wmi, NULL);

	return 0;
}

