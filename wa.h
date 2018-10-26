#ifndef _WA_H_
#define _WA_H_

#include <openssl/evp.h>
#include <pthread.h>
#include <uthash.h>
#include "ws.h"
#include "msg.h"
#include "dispatcher.h"

#define MAX_QUEUE 10

typedef struct
{
	const char *tag;
	pthread_cond_t *cond;
	msg_t *msg;
	UT_hash_handle hh;
} tf_t;

typedef struct
{
	tf_t *tf;
	pthread_mutex_t lock;

	/* Unsolicited message */
	pthread_cond_t cond;
	pthread_cond_t done;
	msg_t *msg;

} rf_t;

typedef struct
{
	/* Session */
	char *client_id;
	char *client_token;
	char *server_token;
	char *browser_token;
	char *secret;
	char *ref;
	EVP_PKEY *keypair;
	EVP_PKEY *peer_key;
	char *pubkey;

	/* Internals */
	int run;
	dispatcher_t *d;
	ws_t *ws;
} wa_t;

wa_t *wa_init();
int wa_login(wa_t *w);
void wa_free(wa_t *w);
void wa_loop(wa_t *w);
msg_t *wa_request(wa_t *w, msg_t *msg);
void wa_msg_free(msg_t *msg);
tf_t *wa_filter_add(rf_t *rf, char *tag);

#endif
