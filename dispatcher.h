#ifndef _DISPATCHER_H_
#define _DISPATCHER_H_

#include "msg.h"
#include "ws.h"

#include <uthash.h>

typedef struct
{
	const char *tag;
	msg_t *msg;

	UT_hash_handle hh;
} reply_t;

typedef struct
{
	/* Used to lock the queue */
	pthread_mutex_t lock;

	/* Pending messages queue */
	reply_t *q;

	/* Unsolicited messages */
	reply_t *u;

	/* Signaled when some msg arrives */
	pthread_cond_t event;

	/* Access to the websocket info */
	ws_t *ws;

	/* Callback function on unsolicited msg */
	int (*u_fn)(msg_t *, void *);
	void *u_user;

} dispatcher_t;


dispatcher_t *
dispatch_init();

int
dispatch_end(dispatcher_t *d);

int
dispatch_events(dispatcher_t *d);

msg_t *
dispatch_request(dispatcher_t *d, const msg_t *msg);

int
dispatch_queue_tag(dispatcher_t *d, const char *tag);

msg_t *
dispatch_wait_reply(dispatcher_t *d, const char *tag);

msg_t *
dispatch_wait_event(dispatcher_t *d, int ms);

#endif
