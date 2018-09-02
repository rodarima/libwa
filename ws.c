#define _DEBUG 1

#include <libwebsockets.h>
#include <string.h>

#define WS_URL "wws://w1.web.whatsapp.com/ws"
#define WS_ORIGIN "https://web.whatsapp.com"

#include "ws.h"

//#define DEBUG



static int interrupted, rx_seen, test, connected=0;

int callback(struct lws* wsi, enum lws_callback_reasons reason, void *user, void* in, size_t len)
{
	//printf("Callback called. Reason %d\n", reason);
	struct ws *w = (struct ws *) user;
	//fprintf(stderr, "got user: %p\n", w);

	switch (reason) {

		/* because we are protocols[0] ... */
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
					in ? (char *)in : "(null)");
			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:
			connected = 1;
			printf("Connection established\n");
			break;

		case LWS_CALLBACK_CLIENT_RECEIVE:
			printf("RX: %s\n", (const char *)in);
			if(w->fn)
				w->fn(w->user, in, len);
			//rx_seen++;
			//if (test && rx_seen == 10)
			interrupted = 1;
			break;

		case LWS_CALLBACK_CLIENT_CLOSED:
			printf("%s: closed\n", __func__);
			interrupted = 1;
			break;

		default:
			break;
	}

	return 0;
}

static struct lws_protocols protocols[] =
{
	{ "test", callback, 0, 0 } ,
	{ NULL, NULL, 0 }
};


int request_QR(struct lws* wsi)
{
#define BUFSIZE 1024

	/*
	char block[LWS_PRE + BUFSIZE];
	char *buf = block[LWS_PRE];
	int copied;

	copied = snprintf(buf, BUFSIZE,
		"[\"admin\",\"%s\",%s,%s,\"%s\",true]",
		action, version, browser, client_id);

	if (copied >= BUFSIZE)
	{
		fprintf(stderr, "BUFSIZE too small, aborting\n");
		return -1;
	}
*/
	//printf("BUFFER: %s\n", generate_client_id());
	//lws_write(wsi, buf, BUFSIZE, LWS_WRITE_TEXT);

#undef BUFSIZE
}

int ws_connect(struct ws *w)
{
	lws_set_log_level(LLL_ERR | LLL_WARN, NULL);
	//lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO |
	//		LLL_DEBUG | LLL_HEADER | LLL_CLIENT, NULL);

	struct lws_context_creation_info params;
	struct lws_client_connect_info info;

	memset(&info, 0, sizeof(info));
	memset(&params, 0, sizeof(params));

	params.port = CONTEXT_PORT_NO_LISTEN;
	params.protocols = protocols;
	params.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		LWS_SERVER_OPTION_JUST_USE_RAW_ORIGIN;

	w->ctx = lws_create_context(&params);
	if (!w->ctx) return 1;

	info.context = w->ctx;

#ifdef DEBUG

	info.ssl_connection = 0;
	info.host = "localhost";
	info.port = 4433;

#else

	info.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED;
	info.host = "w1.web.whatsapp.com";
	info.port = 443;
#endif
	info.address = info.host;
	info.path = "/ws";
	info.origin = "https://web.whatsapp.com";
	info.userdata = (void *) w;
	//info.protocol = protocols[0].name;

	fprintf(stderr, "set user: %p\n", w);

	fprintf(stderr, "Connecting websocket\n");
	w->wsi = lws_client_connect_via_info(&info);

	//lws_set_wsi_user(w->wsi, (void *) w);

	while (!connected)
		lws_service(w->ctx, 50);


}

int ws_loop(struct ws *w)
{
	while (!interrupted)
		lws_service(w->ctx, 50);
}

void ws_free(struct ws *w)
{
	if (w->ctx) lws_context_destroy(w->ctx);
	//if (w->wsi) free(w->wsi);
}

void ws_register_recv_cb(struct ws *w, void (fn)(void *, void *, size_t), void *user)
{
	w->fn = fn;
	w->user = user;
}

void *ws_worker(void *arg)
{
	struct ws *w = (struct ws *) arg;

	fprintf(stderr, "WS thread: were we go!\n");

	while (!w->interrupted)
	{
		lws_service(w->ctx, 500);
		//fprintf(stderr, "WS thread: alive!\n");
		pthread_mutex_lock(w->send_lock);
		pthread_mutex_unlock(w->send_lock);
	}

	fprintf(stderr, "WS thread: bye!\n");

}

int ws_send_buf(struct ws *w, char *buf, size_t len)
{
	int sent;

	fprintf(stderr, "%s: sending %s\n", __func__, buf);

	pthread_mutex_lock(w->send_lock);

	lws_cancel_service(w->ctx);

	sent = lws_write(w->wsi, buf, len, LWS_WRITE_TEXT);

	pthread_mutex_unlock(w->send_lock);

	if(sent != len)
	{
		fprintf(stderr, "%s: lws_write failed\n", __func__);
		return -1;
	}

	return sent;
}

int ws_start(struct ws *w)
{
	pthread_t *th = malloc(sizeof(*th));

	ws_connect(w);

	return pthread_create(th, NULL, ws_worker, (void *) w);
}

struct ws *ws_init()
{
	struct ws *w = malloc(sizeof(*w));

	w->fn = NULL;
	w->user = NULL;
	w->interrupted = 0;

	w->send_lock = malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(w->send_lock, NULL);

	return w;
}


