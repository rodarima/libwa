#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "wa.h"
#include "dispatcher.h"
#include "crypto.h"
#include "bnode.h"
#include "session.h"
#include "l1.h"

#define DEBUG LOG_LEVEL_INFO
#include "log.h"

#define WA_WEB_VERSION "[0,3,1242]"
#define WA_WEB_CLIENT "[\"libwa\",\"Chromium\"]"


static int
action_init(wa_t *wa)
{
	msg_t *msg, *res;
	int len;
	const char *ref;
	json_object *jo, *jref;

	if(!wa->client_id)
	{
		LOG_ERR("client_id is missing\n");
		return -1;
	}

	msg = malloc(sizeof(*msg));

	len = asprintf((char **) &msg->cmd,
		"[\"admin\",\"init\",%s,%s,\"%s\",true]",
		WA_WEB_VERSION, WA_WEB_CLIENT, wa->client_id);

	msg->tag = strdup("init-001");
	msg->len = len;

	res = dispatch_request(wa->d, msg);

	LOG_INFO("Received cmd:%s\n", (char *) res->cmd);

	/* FIXME: The response is NOT null terminated, so the tokenizer reads
	 * outside the buffer */

	assert(((char *) res->cmd)[res->len] == '\0');

	jo = json_tokener_parse(res->cmd);

	assert(jo);

	jref = json_object_object_get(jo, "ref");

	assert(jref);

	ref = json_object_get_string(jref);

	//json_object_put(jref);

	LOG_INFO("Got ref:%s\n", ref);
	wa->ref = strdup(ref);

	json_object_put(jo);


	free(msg->tag);
	free(msg->cmd);
	free(msg);

	free(res->tag);
	free(res->cmd);
	free(res);

	return 0;
}


static int
action_takeover(wa_t *wa)
{
	msg_t *msg;
	size_t len;

	msg = malloc(sizeof(*msg));

	len = asprintf((char **) &msg->cmd,
		"[\"admin\",\"login\",\"%s\",\"%s\",\"%s\",\"takeover\"]",
		wa->client_token,
		wa->server_token,
		wa->client_id);

	msg->tag = strdup("login-001");
	msg->len = len;

	wa->state = WA_STATE_WAIT_CHALLENGE;

	if(dispatch_send_msg(wa->d, msg))
		return -1;

	free(msg->tag);
	free(msg->cmd);
	free(msg);

	return 0;
}












/* Exported symbols */

wa_t *
wa_init(cb_t *cb)
{
	wa_t *wa = calloc(1, sizeof(wa_t));
	wa->run = 1;

	wa->d = dispatch_init();
	wa->c = crypto_init();

	wa->cb = cb;

	wa->users = NULL;
	wa->me = malloc(sizeof(user_t));
	assert(wa->me);

	wa->me->name = "<me>";
	wa->me->jid = "my jid";
	wa->me->notify = "notify?";
	wa->state = WA_STATE_LOGGING;
	wa->keep_alive_next = 0;

	return wa;
}

void
wa_free(wa_t *w)
{
	free(w);
}

int
wa_login(wa_t *wa)
{

	if(session_restore(wa) != 0)
	{
		LOG_INFO("Issuing a new session, restore failed\n");

		/* New session */

		wa->client_id = crypto_generate_client_id();
		if(action_init(wa))
		{
			LOG_ERR("%s: init failed, aborting login\n",
				       __func__);

			return -1;
		}

		LOG_ERR("%s: requesting a new session\n",
			       __func__);

		session_new(wa);
	}
	else
	{
		/* Use the restored session */
		LOG_INFO("Restoring session\n");

		if(action_init(wa))
		{
			LOG_ERR("%s: init failed, aborting login\n",
				       __func__);

			return -1;
		}

		LOG_INFO("Sending takeover\n");
		action_takeover(wa);
	}


	return 0;
}

void
wa_loop(wa_t *wa)
{
	msg_t *msg;

	while(wa->run)
	{
		l1_send_keep_alive(wa);
		msg = dispatch_wait_event(wa->d, 50);
		if(!msg) continue;

		l1_recv_msg(wa, msg);
	}

	dispatch_end(wa->d);
}
