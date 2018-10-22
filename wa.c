#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>
#include <libwebsockets.h>
#include <uthash.h>
#include <assert.h>

#define WA_WEB_VERSION "[0,3,557]"
#define WA_WEB_CLIENT "[\"libwa\",\"Chromium\"]"

#include "wa.h"
#include "ws.h"
#include "crypto.h"


#include <json-c/json.h>

void qr_encode(char *s);

static char *generate_client_id()
{
	//b = secrets.token_bytes(16)
	//b64 = base64.b64encode(b)
	//return b64.decode()

#define RND_BYTES 16
	char buf[RND_BYTES], *client_id;
	if(RAND_bytes((unsigned char *)buf, RND_BYTES) <= 0)
	{
		return NULL;
	}

	client_id = b64_encode(buf, RND_BYTES);

	return client_id;

#undef RND_BYTES
}

int generate_QR(wa_t *wa)
{
	char buf[1024];
	int len;

	len = snprintf(buf, 1024, "%s,%s,%s", wa->ref, wa->pubkey, wa->client_id);
	if (len >= 1024)
		return -1;

	qr_encode(buf);
	printf("QR: %s\n", buf);

	return 0;
}

int wa_action_init(wa_t *wa)
{
#define BUFSIZE 1024

	//char block[LWS_PRE + BUFSIZE];
	msg_t *msg, *res;
	int len;
	char *ref;
	json_object *jo, *jref;

	if(!wa->client_id)
	{
		fprintf(stderr, "client_id is missing\n");
		return -1;
	}

	msg = malloc(sizeof(*msg));
	msg->cmd = malloc(BUFSIZE);

	len = snprintf(msg->cmd, BUFSIZE,
		"[\"admin\",\"init\",%s,%s,\"%s\",true]",
		WA_WEB_VERSION, WA_WEB_CLIENT, wa->client_id);

	if (len >= BUFSIZE)
	{
		fprintf(stderr, "BUFSIZE too small, aborting\n");
		return -1;
	}

	msg->tag = strdup("init-001");

	res = wa_request(wa, msg);

	fprintf(stderr, "Received cmd:%s\n", (char *) res->cmd);

	jo = json_tokener_parse(res->cmd);

	jref = json_object_object_get(jo, "ref");

	ref = strdup(json_object_get_string(jref));

	//json_object_put(jref);
	json_object_put(jo);

	printf("Got ref:%s\n", ref);
	wa->ref = ref;

	generate_QR(wa);

	wa_msg_free(msg);
	wa_msg_free(res);

#undef BUFSIZE

	return 0;
}

rf_t *wa_recv_filter_init()
{
	rf_t *rf = calloc(sizeof(*rf), 1);

	rf->lock = malloc(sizeof(*(rf->lock)));
	pthread_mutex_init(rf->lock, NULL);

	rf->tf = NULL;

	return rf;
}

void wa_free(wa_t *w)
{
	if(w->client_id) free(w->client_id);
	//ws_free(w);
	free(w);
}

int wa_login(wa_t *w)
{
	w->client_id = generate_client_id(w);
	wa_action_init(w);

	//ws_join(w->ws);
	return 0;
}


msg_t *wa_msg_init(char *tag, char *cmd)
{
	msg_t *msg = malloc(sizeof(*msg));
	msg->tag = tag;
	msg->cmd = cmd;

	return msg;
}

void wa_msg_free(msg_t *msg)
{
	//free(msg->tag);
	//free(msg->cmd);
	free(msg);
}

char *wa_msg_to_buf(msg_t *msg, char **alloc_buf, size_t *len)
{
	size_t size = strlen(msg->tag) + strlen(msg->cmd) + 1;
	char *buf = malloc(LWS_PRE + size + 1);
	char *msg_buf = buf + LWS_PRE;

	strcpy(msg_buf, msg->tag);
	strcat(msg_buf, ",");
	strcat(msg_buf, msg->cmd);

	if (msg_buf[size] != '\0')
	{
		printf("Error, buffer is not null terminated");
		return NULL;
	}

	*alloc_buf = buf;
	*len = size;
	return msg_buf;
}

msg_t *wa_packet_to_msg(packet_t *pkt)
{
	char *sep;
	void *cmd;

	msg_t *msg = malloc(sizeof(*msg));

	sep = strchr(pkt->buf, ',');
	assert(sep);
	*sep = '\0';
	cmd = sep + 1;

	// We copy here the whole message again...

	msg->tag = strdup(pkt->buf);
	msg->len = pkt->total - strlen(msg->tag) - 1;
	msg->cmd = malloc(msg->len);
	assert(msg->cmd);
	memcpy(msg->cmd, cmd, msg->len);

	// WARNING: It may not be null terminated!

	return msg;
}

int wa_send_buf(wa_t *w, char *buf, size_t len)
{
	int sent;

	fprintf(stderr, "%s: sending %s\n", __func__, buf);

	sent = lws_write(w->ws->wsi, (unsigned char *) buf, len, LWS_WRITE_TEXT);

	if(sent != len)
	{
		fprintf(stderr, "%s: lws_write failed\n", __func__);
		return -1;
	}

	return sent;
}

int wa_send(wa_t *w, msg_t *msg)
{
	char *alloc_buf, *buf;
	size_t len;

	buf = wa_msg_to_buf(msg, &alloc_buf, &len);

	if (!buf)
		return -1;

	ws_send_buf(w->ws, buf, len);

	free(alloc_buf);

	return 0;
}


msg_t *wa_filter_recv(rf_t *rf, tf_t *tf)
{
	msg_t *msg;

	pthread_mutex_lock(rf->lock);
	//TODO: timedwait
	pthread_cond_wait(tf->cond, rf->lock);
	fprintf(stderr, "%s: Received signal for tag: %s\n",
			__func__, tf->tag);
	msg = tf->msg;
	pthread_mutex_unlock(rf->lock);

	free(tf);

	return msg;

}

msg_t *wa_request(wa_t *wa, msg_t *msg)
{
	tf_t *tf;

	tf = wa_filter_add(wa->rf, msg->tag);

	fprintf(stderr, "Sending msg:\n\ttag:%s\n\tcmd:%s\n",
		       msg->tag, (char *) msg->cmd);

	wa_send(wa, msg);

	return wa_filter_recv(wa->rf, tf);
}

tf_t *wa_filter_add(rf_t *rf, char *tag)
{
	tf_t *tf = malloc(sizeof(*tf));

	tf->tag = tag;
	tf->cond = malloc(sizeof(*(tf->cond)));
	pthread_cond_init(tf->cond, NULL);

	pthread_mutex_lock(rf->lock);

	HASH_ADD_KEYPTR(hh, rf->tf, tf->tag, strlen(tf->tag), tf);

	pthread_mutex_unlock(rf->lock);

	return tf;
}


int wa_recv_msg(rf_t *rf, msg_t *msg)
{
	int found = 0;
	const char *tag = msg->tag;
	tf_t *tf;

	pthread_mutex_lock(rf->lock);

	HASH_FIND_STR(rf->tf, tag, tf);

	fprintf(stderr, "%s: received msg tag:%s\n", __func__, msg->tag);

	if (!tf)
	{
		//Drop
		fprintf(stderr, "DROP: tag:%s cmd:%s\n",
				msg->tag, (char *) msg->cmd);
	}
	else
	{
		found = 1;
		tf->msg = msg;
		fprintf(stderr, "ACCEPTED: tag:%s cmd:%s\n",
			       msg->tag, (char *) msg->cmd);

		HASH_DEL(rf->tf, tf);
		// Free tf here?
		// No, the other thread is still waiting on tf->cond
	}

	pthread_mutex_unlock(rf->lock);

	if(found)
		pthread_cond_signal(tf->cond);

	return found;
}


void wa_recv_packet_cb(packet_t *pkt, void *user)
{
	rf_t *rf = (rf_t *) user;

	msg_t *msg = wa_packet_to_msg(pkt);;

	if(!msg)
		return;

	if (!wa_recv_msg(rf, msg))
	{
		/* TODO: Don't drop, place in queue and signal main cond */

		/* Free */
		wa_msg_free(msg);
	}
}

int wa_keys_init(wa_t *w)
{
	if(generate_keys(&(w->keypair)))
		return -1;

	w->pubkey = get_public_key(w->keypair);
	if(!w->pubkey)
		return -1;

	return 0;
}

void wa_loop(wa_t *w)
{
	pthread_join(w->ws->worker, NULL);
}

wa_t *wa_init()
{
	wa_t *w = calloc(1, sizeof(wa_t));

	w->rf = wa_recv_filter_init();
	w->ws = ws_init();

	wa_keys_init(w);

	ws_register_recv_cb(w->ws, wa_recv_packet_cb, (void *) w->rf);

	ws_start(w->ws);

	return w;
}
