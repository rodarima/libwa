#include "dispatcher.h"

#include <assert.h>
#include <libwebsockets.h>

#include "wa.h"
#include "ws.h"

static msg_t *
packet_to_msg(packet_t *pkt)
{
	char *sep;
	void *cmd;

	msg_t *msg = malloc(sizeof(msg_t));

	/* Find the tag */
	sep = memchr(pkt->buf, ',', pkt->total);
	assert(sep);

	/* Terminate the tag string */
	*sep = '\0';
	cmd = sep + 1;

	// We copy here the whole message again and add one extra byte for NULL
	// terminate a possible JSON string

	msg->tag = strdup(pkt->buf);
	assert(msg->tag);
	msg->len = pkt->total - strlen(msg->tag) - 1;
	msg->cmd = malloc(msg->len + 1);
	assert(msg->cmd);
	memcpy(msg->cmd, cmd, msg->len);

	/* Ensure NULL terminating cmd */
	((char *) msg->cmd)[msg->len] = '\0';

	return msg;
}

static packet_t *
msg_to_packet(const msg_t *msg)
{
	packet_t *pkt = malloc(sizeof(*pkt));
	assert(pkt);

	size_t taglen = strlen(msg->tag);

	pkt->total = taglen + 1 + msg->len;
	pkt->buf = malloc(LWS_PRE + pkt->total);
	assert(pkt->buf);
	pkt->end = pkt->buf + LWS_PRE;

	/* Copy the tag and cmd */
	memcpy(pkt->end, msg->tag, taglen);
	pkt->end += taglen;
	*((char*)pkt->end) = ',';
	pkt->end++;

	/* Note that if '\0' is needed, the len has to include it */
	memcpy(pkt->end, msg->cmd, msg->len);

	/* Keep the end pointer to the begining of our data */
	pkt->end = pkt->buf + LWS_PRE;

	return pkt;
}

//int
//dispatch_unsol_queue(wa_t *wa, dipatch_t *d)
//{
//	reply_t *r, *tmp;
//
//	HASH_ITER(hh, d->u, reply, tmp) {
//		wa_handle_msg(wa, reply->msg);
//		HASH_DEL(d->u, reply);
//		free(reply);
//	}
//
//	return 0;
//}

static int
dispatch_recv_msg(dispatcher_t *d, msg_t *msg)
{
	reply_t *pending, *unsol;

	pthread_mutex_lock(&d->lock);

	/* Find a matching tag in pending queue fist */
	HASH_FIND_STR(d->q, msg->tag, pending);

	if(pending)
	{
		/* A matching tag was found, save in the proper place */
		fprintf(stderr, "MATCH tag:%s\n", msg->tag);
		pending->msg = msg;
		pthread_cond_signal(&d->event);
		/* Don't free msg, the other thread is still waiting on
		 * pending->cond */
	}
	else
	{
		/* Seems like an unsolicited msg arrived */
		HASH_FIND_STR(d->u, msg->tag, unsol);

		/* Ensure no other tag already in the unsolicited queue */
		if(unsol)
		{
			fprintf(stderr, "DUP tag:%s\n", msg->tag);
			return 1;
		}

		unsol = malloc(sizeof(reply_t));
		assert(unsol);
		unsol->msg = msg;

		HASH_ADD_KEYPTR(hh, d->u, msg->tag, strlen(msg->tag), unsol);
		pthread_cond_signal(&d->event);
	}

	pthread_mutex_unlock(&d->lock);

	return 0;
}

static int
dispatch_recv_packet(packet_t *pkt, void *user)
{
	dispatcher_t *d = (dispatcher_t *) user;

	msg_t *msg = packet_to_msg(pkt);

	fprintf(stderr, "RECV tag:%s\n", msg->tag);

	if(!msg)
		return -1;

	if (dispatch_recv_msg(d, msg))
	{
		/* Message not wanted */
		fprintf(stderr, "DROP tag:%s\n", msg->tag);

		/* Free */
		free(msg->tag);
		free(msg->cmd);
		free(msg);
	}

	return 0;
}

static int
dispatch_send_msg(dispatcher_t *d, const msg_t *msg)
{
	size_t sent;
	packet_t *pkt = msg_to_packet(msg);
	assert(pkt);

	sent = ws_send_pkt(d->ws, pkt);

	free(pkt->buf);

	if(sent != pkt->total)
	{
		free(pkt);
		return -1;
	}

	free(pkt);

	return 0;
}

static int
dispatch_queue_tag(dispatcher_t *d, const char *tag)
{
	reply_t *r;
	pthread_mutex_lock(&d->lock);
	HASH_FIND_STR(d->q, tag, r);

	if(r)
	{
		/* Already requested with the same tag: FAIL */
		pthread_mutex_unlock(&d->lock);
		return -1;
	}

	r = malloc(sizeof(reply_t));
	assert(r);

	msg_t *msg = malloc(sizeof(msg_t));
	assert(msg);

	msg->tag = strdup(tag);
	r->msg = msg;

	HASH_ADD_KEYPTR(hh, d->q, tag, strlen(tag), r);

	pthread_mutex_unlock(&d->lock);

	return 0;
}

//int
//dispatch_loop(dispatcher_t *d, struct timespec until)
//{
//	/* Look for unsolicited messages */
//	dispatch_unsol_queue(d);
//
//	/* Maybe attend timeouts? */
//	return 0;
//}

static msg_t *
dispatch_wait_reply(dispatcher_t *d, const char *tag)
{
	reply_t *reply;
	msg_t *msg;

	pthread_mutex_lock(&d->lock);

	while(1) {
		pthread_cond_wait(&d->event, &d->lock);
		HASH_FIND_STR(d->q, tag, reply);

		/* If our reply has arrived, return inmediately */
		if(reply)
			break;
	}

	HASH_DEL(d->q, reply);

	pthread_mutex_unlock(&d->lock);

	msg = reply->msg;

	free(reply);

	return msg;
}

msg_t *
dispatch_request(dispatcher_t *d, const msg_t *msg)
{
	if(dispatch_queue_tag(d, msg->tag))
	{
		return NULL;
	}

	if(dispatch_send_msg(d, msg))
	{
		/* TODO: Unqueue tag */
		return NULL;
	}

	return dispatch_wait_reply(d, msg->tag);
}

dispatcher_t *
dispatch_init()
{
	dispatcher_t *d = malloc(sizeof(dispatcher_t));

	/* Create a new websocket */
	d->ws = ws_init();

	pthread_cond_init(&d->event, NULL);
	pthread_mutex_init(&d->lock, NULL);

	/* Init hash tables */
	d->q = NULL;
	d->u = NULL;

	/* Set the callback to recv in websocket */
	ws_register_recv_cb(d->ws, dispatch_recv_packet, (void *) d);

	/* And start the worker thread */
	ws_start(d->ws);

	return d;
}

int
dispatch_events(dispatcher_t *d)
{
	return 0;
}

int
dispatch_end(dispatcher_t *d)
{
	fprintf(stderr, "Waiting for WS to finish...\n");
	/* TODO: Avoid entering ws struct from here, use ws_stop() */
	pthread_join(d->ws->worker, NULL);
	return 0;
}
