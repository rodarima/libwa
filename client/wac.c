#include <stdio.h>
#include "wa.h"

int
cb_priv_msg(void *ptr, priv_msg_t *msg)
{
	printf("%s: %s\n", msg->from->name, msg->text);
	return 0;
}

int
cb_update_user(void *ptr, user_t *u)
{
	//printf("New user: %s (%s)\n", u->name, u->jid);
	return 0;
}

int
main(int argc, char *argv[])
{
	int wait = 0;
	char *jid, *msg;

	jid = argv[1];
	msg = argv[2];

	if(msg == NULL)
		msg = "This is a test message from libwa";

	cb_t cb =
	{
		.ptr = NULL,
		.priv_msg = cb_priv_msg,
		.update_user = cb_update_user,
	};

	wa_t *wa = wa_init(&cb);

	wa_login(wa);
	while(wa->run)
	{
		wa_dispatch(wa, 50);
		wait++;
		if(wait == 100)
		{
			printf("SENDING MSG...\n");
			wa_send_priv_msg(wa, jid, msg);
		}
	}
	wa_free(wa);


	return 0;
}

