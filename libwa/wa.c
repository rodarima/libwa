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
#include "l4.h"
#include "chat.h"

#define DEBUG LOG_LEVEL_DEBUG
#include "log.h"

#define WA_WEB_VERSION "[0,3,9309]"
#define WA_WEB_CLIENT "[\"libwa\",\"Chromium\"]"


static int
action_init(wa_t *wa)
{
	struct timespec tp;
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


	clock_gettime(CLOCK_REALTIME, &tp);
	wa->login_time = tp.tv_sec;

	asprintf(&msg->tag, "%ld.--%d", wa->login_time, wa->tag_counter++);
	msg->len = len;

	res = dispatch_request(wa->d, msg, 0);

	LOG_INFO("Received cmd:%s\n", (char *) res->cmd);

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

	asprintf(&msg->tag, "%ld.--%d", wa->login_time, wa->tag_counter++);
	msg->len = len;

	wa->state = WA_STATE_WAIT_CHALLENGE;

	if(dispatch_send_msg(wa->d, msg, 0))
		return -1;

	free(msg->tag);
	free(msg->cmd);
	free(msg);

	return 0;
}












/* Exported symbols */

wa_t *
wa_init(cb_t *cb, const char *config_dir)
{
	wa_t *wa = calloc(1, sizeof(wa_t));
	wa->run = 1;

	wa->d = dispatch_init();
	wa->c = crypto_init();
	wa->chat = chat_init();

	wa->cb = cb;

	wa->msg_counter = 1;
	wa->users = NULL;
	wa->me = malloc(sizeof(user_t));
	assert(wa->me);

	wa->me->name = "<me>";
	wa->me->jid = "my jid";
	wa->me->notify = "notify?";
	wa->state = WA_STATE_LOGGING;
	wa->keep_alive_next = 0;

	wa->s = wa_storage_init(config_dir);
	wa->last_forwarded = 0;
	wa->last_timestamp = 0;

	return wa;
}

void
wa_free(wa_t *w)
{
	w->run = 0;
	dispatch_free(w->d);
	crypto_free(w->c);
	storage_free(w->s);
	free(w);
}

int
wa_login(wa_t *wa)
{
	int restore_failed;

	restore_failed = (session_restore(wa) != 0);

	if(restore_failed)
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

		LOG_INFO("%s: requesting a new session\n",
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

	while(wa->run)
	{
		if(wa->state == WA_STATE_LOGGED_IN)
			break;

		if(wa->state == WA_STATE_LOGIN_FAILED)
			return -1;

		wa_dispatch(wa, 50);
	}

	if(restore_failed)
	{
		if(session_save(wa) != 0)
		{
			LOG_ERR("Saving session failed!\n");
			return -1;
		}
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
		free(msg->tag);
		free(msg->cmd);
		free(msg);
	}
}

void
wa_dispatch(wa_t *wa, int ms)
{
	msg_t *msg;

	if(wa->run)
	{
		l1_send_keep_alive(wa);
		msg = dispatch_wait_event(wa->d, ms);
		if(!msg) return;

		l1_recv_msg(wa, msg);
		free(msg->tag);
		free(msg->cmd);
		free(msg);
	}
}

int
wa_send_priv_msg(wa_t *wa, char *to_jid, char *text)
{
	//return l1_presence_suscribe(wa);
	return l4_send_priv_msg(wa, to_jid, text);
}
