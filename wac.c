#include <stdio.h>
#include "wa.h"
#include "session.h" /* XXX: This should disappear */

int
cb_priv_msg(void *ptr, priv_msg_t *msg)
{
	printf("%s: %s\n", msg->from->name, msg->text);
	return 0;
}

int
cb_update_user(void *ptr, user_t *u)
{
	printf("New user: %s (%s)\n", u->name, u->jid);
	return 0;
}

int
main(int argc, char *argv[])
{
	cb_t cb =
	{
		.ptr = NULL,
		.priv_msg = cb_priv_msg,
		.update_user = cb_update_user,
	};

	wa_t *wa = wa_init(&cb);

	wa_login(wa);
	wa_loop(wa);
	wa_free(wa);


	return 0;
}

