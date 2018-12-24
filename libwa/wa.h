#pragma once

#include <openssl/evp.h>
#include <pthread.h>
#include <uthash.h>
#include <time.h>

#include "ws.h"
#include "msg.h"
#include "buf.h"
#include "crypto.h"
#include "dispatcher.h"

#define MAX_QUEUE 10

enum wa_state
{
	WA_STATE_LOGGING = 0,
	WA_STATE_LOGGED_IN,
	WA_STATE_WAIT_CHALLENGE,
	WA_STATE_SENT_CHALLENGE,
	WA_STATE_LOGIN_FAILED,
	WA_STATE_READY,
};

typedef struct
{
	char *name;
	char *notify;
	char *jid;

	UT_hash_handle hh;
} user_t;

typedef struct
{
	char *text;
	user_t *from;
	user_t *to;
} priv_msg_t;

typedef struct
{
	/* User ptr */
	void *ptr;

	/* Callbacks */
	int (*priv_msg)(void *, priv_msg_t *);
	int (*update_user)(void *, user_t *);

} cb_t;


typedef struct
{
	/* In base64 */
	char *client_id;
	char *client_token;
	char *server_token;
	char *browser_token;
	char *secret;
	char *ref;
	char *pubkey;


	/* Hash map using jid as keys */
	user_t *users;

	/* Just a single user */
	user_t *me;

	/* Internals */
	int run;
	int state;
	time_t keep_alive_next;
	int msg_counter;
	int tag_counter;
	time_t login_time;
	dispatcher_t *d;
	crypto_t *c;
	cb_t *cb;
} wa_t;


wa_t *
wa_init(cb_t *cb);

int
wa_login(wa_t *w);

void
wa_free(wa_t *w);

void
wa_loop(wa_t *w);

msg_t *
wa_request(wa_t *wa, msg_t *msg);

int
wa_send_priv_msg(wa_t *wa, char *to_jid, char *text);


void
wa_dispatch(wa_t *wa, int ms);
