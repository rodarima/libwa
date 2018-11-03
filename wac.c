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
main()
{
	wa_t *wa = wa_init();
	wa_cb_priv_msg(wa, NULL, cb_priv_msg);
	wa_login(wa);

	wa_loop(wa);
	wa_free(wa);


	return 0;
}

