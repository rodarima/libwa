#ifndef _WS_H_
#define _WS_H_

#include <pthread.h>

typedef struct
{
	void *buf;
	void *end;
	size_t stored;
	size_t total;
} packet_t;

typedef struct
{
	void (*recv_fn)(packet_t *, void *);
	void *recv_user;

	packet_t partial;

	struct lws *wsi;
	struct lws_context *ctx;

	int interrupted;
	int connected;

	pthread_mutex_t *send_lock;
	pthread_t worker;
} ws_t;

ws_t *ws_init();
int ws_start(ws_t *ws);
int ws_send_buf(ws_t *ws, char *buf, size_t len);
void ws_register_recv_cb(ws_t *ws, void (*fn)(packet_t *, void *), void *user);

#endif
