#define _DEBUG 1 /* Debug libwebsockets */

#include <libwebsockets.h>
#include <string.h>

#define WS_URL "wws://w1.web.whatsapp.com/ws"
#define WS_ORIGIN "https://web.whatsapp.com"

#include "ws.h"

#define DEBUG_SERVER 0

#define DEBUG LOG_LEVEL_DEBUG
#include "log.h"

static int
ws_recv(ws_t *ws, void *in, size_t len, size_t remaining)
{
	packet_t *partial = &ws->partial;

	// If is a new packet, allocate the space
	if(!partial->buf)
	{
		size_t total = len + remaining;
		partial->buf = malloc(total);
		partial->total = total;
		partial->end = partial->buf;
		partial->stored = 0;
	}

	if(partial->stored + len > partial->total)
	{
		fprintf(stderr, "%s: FATAL: packet exceeds total size %lu\n",
			       __func__, partial->total);
		//TODO: What should we do if this happens? Discard the
		//frame?
		abort();
	}

	// Copy the fragment
	memcpy(partial->end, in, len);
	partial->end += len;
	partial->stored += len;

	// Packet complete
	if(partial->stored == partial->total)
	{
		if(ws->recv_fn)
			ws->recv_fn(partial, ws->recv_user);

		free(partial->buf);
		partial->buf = NULL;
		partial->end = NULL;
		partial->total = 0;
		partial->stored = 0;
	}

	return 0;
}

int
callback(struct lws* wsi, enum lws_callback_reasons reason, void *user,
		void* in, size_t len)
{
	LOG_DEBUG("Callback called. Reason %d\n", reason);
	ws_t *ws = (ws_t *) user;
	size_t remaining;

	switch (reason) {

		/* because we are protocols[0] ... */
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
					in ? (char *)in : "(null)");
			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:
			ws->connected = 1;
			printf("Connection established\n");
			break;

		case LWS_CALLBACK_CLIENT_RECEIVE:
			remaining = lws_remaining_packet_payload(wsi);
			//printf("RX(%lu)\n", len);
			ws_recv(ws, in, len, remaining);
			break;

		case LWS_CALLBACK_CLIENT_CLOSED:
			printf("%s: closed\n", __func__);
			ws->interrupted = 1;
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

int ws_connect(ws_t *ws)
{
	lws_set_log_level(LLL_ERR | LLL_WARN, NULL);
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO |
			LLL_DEBUG | LLL_HEADER | LLL_CLIENT, NULL);

	struct lws_context_creation_info params;
	struct lws_client_connect_info info;

	memset(&info, 0, sizeof(info));
	memset(&params, 0, sizeof(params));

	params.port = CONTEXT_PORT_NO_LISTEN;
	params.protocols = protocols;
	params.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		LWS_SERVER_OPTION_JUST_USE_RAW_ORIGIN;
	//params.client_ssl_ca_filepath = "/home/ram/dev/whatsapp/libwa/certs/DigiCert_High_Assurance_EV_Root_CA.pem";

	ws->ctx = lws_create_context(&params);
	if (!ws->ctx) return 1;

	info.context = ws->ctx;

#if DEBUG_SERVER

	info.ssl_connection = 0;
	info.host = "localhost";
	info.port = 4433;

#else

	info.ssl_connection = LCCSCF_USE_SSL;
	//| LCCSCF_ALLOW_SELFSIGNED;
	info.host = "w1.web.whatsapp.com";
	info.port = 443;
#endif
	info.address = info.host;
	info.path = "/ws";
	info.origin = "https://web.whatsapp.com";

	/* Here we set the pointer to our own data, available in the callback */
	info.userdata = (void *) ws;
	//info.protocol = protocols[0].name;

	fprintf(stderr, "set user: %p\n", ws);

	fprintf(stderr, "Connecting websocket\n");
	ws->wsi = lws_client_connect_via_info(&info);

	while (!ws->connected)
		lws_service(ws->ctx, 50);

	return 0;
}

int ws_loop(ws_t *ws)
{
	while (!ws->interrupted)
		lws_service(ws->ctx, 50);

	return 0;
}

void ws_free(ws_t *w)
{
	if (w->ctx) lws_context_destroy(w->ctx);
	//if (w->wsi) free(w->wsi);
}

void ws_register_recv_cb(ws_t *ws, int (fn)(packet_t*, void *), void *user)
{
	ws->recv_fn = fn;
	ws->recv_user = user;
}

void *ws_worker(void *arg)
{
	ws_t *ws = (ws_t *) arg;

	fprintf(stderr, "WS thread: were we go!\n");

	while (!ws->interrupted)
	{
		//pthread_mutex_lock(ws->send_lock);
		//LOG_DEBUG("Locked ws->send_lock\n");
		lws_service(ws->ctx, 50);
		//fprintf(stderr, "WS thread: alive!\n");
		//pthread_mutex_unlock(ws->send_lock);
		//LOG_DEBUG("Unlocked ws->send_lock\n");
	}

	fprintf(stderr, "WS thread: bye!\n");

	return 0;
}


int
ws_send_pkt(ws_t *ws, packet_t *pkt)
{
	int sent;

	pthread_mutex_lock(ws->send_lock);

	lws_cancel_service(ws->ctx);

	sent = lws_write(ws->wsi, (unsigned char *) pkt->end, pkt->total,
			LWS_WRITE_TEXT);

	pthread_mutex_unlock(ws->send_lock);

	if(sent != pkt->total)
	{
		fprintf(stderr, "%s: lws_write failed\n", __func__);
		return -1;
	}

	return sent;
}

int ws_send_buf(ws_t *ws, char *buf, size_t len)
{
	int sent;

	fprintf(stderr, "%s: sending %s\n", __func__, buf);

	pthread_mutex_lock(ws->send_lock);

	lws_cancel_service(ws->ctx);

	sent = lws_write(ws->wsi, (unsigned char *) buf, len, LWS_WRITE_TEXT);

	pthread_mutex_unlock(ws->send_lock);

	if(sent != len)
	{
		fprintf(stderr, "%s: lws_write failed\n", __func__);
		return -1;
	}

	return sent;
}

int ws_start(ws_t *ws)
{
	ws_connect(ws);

	return pthread_create(&ws->worker, NULL, ws_worker, (void *) ws);
}

ws_t *ws_init()
{
	ws_t *ws = calloc(sizeof(*ws), 1);

	if(!ws) return ws;

	ws->send_lock = malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(ws->send_lock, NULL);

	return ws;
}


