#ifndef _WS_H_
#define _WS_H_

#include <pthread.h>

struct ws
{
	void (*fn)(void *, void *, size_t);
	void *user;
	struct lws *wsi;
	struct lws_context *ctx;
	int interrupted;
	pthread_mutex_t *send_lock;
};

struct ws *ws_init();
int ws_start(struct ws *w);
int ws_send_buf(struct ws *w, char *buf, size_t len);
void ws_register_recv_cb(struct ws *w, void (*fn)(void *, void *, size_t), void *user);

#endif
