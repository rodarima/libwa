#include <stdio.h>
#include "wa.h"

char *jid = NULL;
wa_t *wa = NULL;

int
cb_priv_msg(void *ptr, priv_msg_t *msg)
{
	printf("%s\n", msg->text);
	fflush(stdout);
	return 0;
}

int
cb_update_user(void *ptr, user_t *u)
{
	//printf("New user: %s (%s)\n", u->name, u->jid);
	return 0;
}

void *
input_worker(void *ptr)
{
	char *line;
	size_t len;

	while(1)
	{
		line = NULL;
		len = 0;
		getline(&line, &len, stdin);

		/* Remove new line */
		line[strlen(line) - 1] = '\0';

		if(strlen(line) > 0)
			wa_send_priv_msg(wa, jid, line);

		free(line);
	}
	return NULL;
}

int
main(int argc, char *argv[])
{
	pthread_t th;

	jid = argv[1];

	cb_t cb =
	{
		.ptr = NULL,
		.priv_msg = cb_priv_msg,
		.update_user = cb_update_user,
	};

	wa = wa_init(&cb);

	wa_login(wa);
	printf("#ready\n");
	fflush(stdout);

	pthread_create(&th, NULL, input_worker, NULL);

	while(wa->run)
	{
		wa_dispatch(wa, 50);
	}
	wa_free(wa);


	return 0;
}

