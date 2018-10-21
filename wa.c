#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>
#include <libwebsockets.h>
#include <uthash.h>

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
	if(RAND_bytes(buf, RND_BYTES) <= 0)
	{
		return NULL;
	}

	client_id = b64_encode(buf, RND_BYTES);

	return client_id;

#undef RND_BYTES
}

int generate_QR(struct wa *w)
{
	char buf[1024];
	int len;

	len = snprintf(buf, 1024, "%s,%s,%s", w->ref, w->pubkey, w->client_id);
	if (len >= 1024)
		return -1;

	qr_encode(buf);
	printf("QR: %s\n", buf);
}

int wa_action_init(struct wa *w)
{
#define BUFSIZE 1024

	//char block[LWS_PRE + BUFSIZE];
	struct wa_msg *msg, *res;
	int len;
	char *ref;
	json_object *jo, *jref;

	if(!w->client_id)
	{
		fprintf(stderr, "client_id is missing\n");
		return -1;
	}

	msg = malloc(sizeof(*msg));
	msg->cmd = malloc(BUFSIZE);

	len = snprintf(msg->cmd, BUFSIZE,
		"[\"admin\",\"init\",%s,%s,\"%s\",true]",
		WA_WEB_VERSION, WA_WEB_CLIENT, w->client_id);

	if (len >= BUFSIZE)
	{
		fprintf(stderr, "BUFSIZE too small, aborting\n");
		return -1;
	}

	msg->tag = strdup("init-001");

	res = wa_request(w, msg);

	fprintf(stderr, "Received cmd:%s\n", res->cmd);

	jo = json_tokener_parse(res->cmd);

	jref = json_object_object_get(jo, "ref");

	ref = strdup(json_object_get_string(jref));

	//json_object_put(jref);
	json_object_put(jo);

	printf("Got ref:%s\n", ref);
	w->ref = ref;

	generate_QR(w);

	wa_msg_free(msg);
	wa_msg_free(res);

#undef BUFSIZE

	return 0;
}

struct recv_filter *wa_recv_filter_init()
{
	struct recv_filter *rf = calloc(sizeof(*rf), 1);

	rf->lock = malloc(sizeof(*(rf->lock)));
	pthread_mutex_init(rf->lock, NULL);

	rf->tf = NULL;

	return rf;
}

void wa_free(struct wa *w)
{
	if(w->client_id) free(w->client_id);
	//ws_free(w);
	free(w);
}

int wa_login(struct wa *w)
{
	w->client_id = generate_client_id(w);
	wa_action_init(w);

	//ws_join(w->ws);
}


struct wa_msg *wa_msg_init(char *tag, char *cmd)
{
	struct wa_msg *msg = malloc(sizeof(*msg));
	msg->tag = tag;
	msg->cmd = cmd;

	return msg;
}

void wa_msg_free(struct wa_msg *msg)
{
	//free(msg->tag);
	//free(msg->cmd);
	free(msg);
}

char *wa_msg_to_buf(struct wa_msg *msg, char **alloc_buf, size_t *len)
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

int wa_buf_to_msg(char *buf, size_t len, struct wa_msg **msg_ptr)
{
	char *sep;
	struct wa_msg *msg = malloc(sizeof(*msg));

	sep = strchr(buf, ',');
	*sep = '\0';

	msg->tag = buf;
	msg->cmd = sep + 1;

	*msg_ptr = msg;
	return 0;
}

int wa_send_buf(struct wa *w, char *buf, size_t len)
{
	int sent;

	fprintf(stderr, "%s: sending %s\n", __func__, buf);

	sent = lws_write(w->ws->wsi, buf, len, LWS_WRITE_TEXT);

	if(sent != len)
	{
		fprintf(stderr, "%s: lws_write failed\n", __func__);
		return -1;
	}

	return sent;
}

int wa_send(struct wa *w, struct wa_msg *msg)
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


struct wa_msg *wa_filter_recv(struct recv_filter *rf, struct tag_filter *tf)
{
	struct wa_msg *msg;

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

struct wa_msg *wa_request(struct wa *w, struct wa_msg *msg)
{
	struct tag_filter *tf;

	tf = wa_filter_add(w->rf, msg->tag);

	fprintf(stderr, "Sending msg:\n\ttag:%s\n\tcmd:%s\n",
		       msg->tag, msg->cmd);

	wa_send(w, msg);

	return wa_filter_recv(w->rf, tf);
}

struct tag_filter *wa_filter_add(struct recv_filter *rf, char *tag)
{
	struct tag_filter *tf = malloc(sizeof(*tf));

	tf->tag = tag;
	tf->cond = malloc(sizeof(*(tf->cond)));
	pthread_cond_init(tf->cond, NULL);

	pthread_mutex_lock(rf->lock);

	HASH_ADD_KEYPTR(hh, rf->tf, tf->tag, strlen(tf->tag), tf);

	pthread_mutex_unlock(rf->lock);

	return tf;
}


struct tag_filter *wa_recv_cb(struct recv_filter *rf, struct wa_msg *msg)
{

	const char *tag = msg->tag;
	struct tag_filter *tf;

	pthread_mutex_lock(rf->lock);

	HASH_FIND_STR(rf->tf, tag, tf);

	fprintf(stderr, "%s: received msg tag:%s\n", __func__, msg->tag);

	if (!tf)
	{
		//Drop
		fprintf(stderr, "DROP: %s\n", msg->tag);
	}
	else
	{
		tf->msg = msg;
		pthread_cond_signal(tf->cond);
		fprintf(stderr, "ACCEPTED: tag:%s cmd:%s\n",
			       msg->tag, msg->cmd);

		HASH_DEL(rf->tf, tf);
		// XXX: Free tf here?
	}

	pthread_mutex_unlock(rf->lock);

	return tf;
}


void wa_recv_buf_cb(void *user, void *data, size_t len, size_t remaining)
{
	struct recv_filter *rf = (struct recv_filter *) user;
	char *buf = NULL;
	struct wa_msg *msg;
	size_t total_size = len + remaining;
	size_t acc;

	if(rf->buf)
	{
		acc = rf->ptr - rf->buf + len;
		if(acc > rf->buf_size)
		{
			fprintf(stderr, "%s: FATAL buf_size exceeded buf_size:%d accum_len:%d\n",
				       __func__, rf->buf_size, acc);
			abort();
		}

		memcpy(rf->ptr, data, len);
		rf->ptr += len;

		if(!remaining)
		{
			buf = rf->buf;
			rf->buf = NULL;
			rf->ptr = NULL;
		}
	}
	else
	{
		if(remaining)
		{
			rf->buf_size = total_size + 1;
			rf->buf = malloc(total_size + 1);
			rf->ptr = rf->buf;

			memcpy(rf->ptr, data, len);
			rf->ptr += len;
		}
		else
		{
			buf = malloc(total_size + 1);
			memcpy(buf, data, len);
		}
	}


	if (!buf)
		return;

	buf[total_size] = '\0';
	wa_buf_to_msg(buf, total_size, &msg);

	if (!wa_recv_cb(rf, msg))
	{
		/* TODO: Don't drop, place in queue and signal main cond */

		/* Drop */
		free(buf);
		wa_msg_free(msg);
	}
}

int wa_keys_init(struct wa *w)
{
	if(generate_keys(&(w->keypair)))
		return -1;

	w->pubkey = get_public_key(w->keypair);
	if(!w->pubkey)
		return -1;

	return 0;
}

void wa_loop(struct wa *w)
{
	pthread_join(w->ws->worker, NULL);
}

struct wa *wa_init()
{
	struct wa *w = calloc(1, sizeof(struct wa));

	w->rf = wa_recv_filter_init();
	w->ws = ws_init();

	wa_keys_init(w);

	ws_register_recv_cb(w->ws, wa_recv_buf_cb, (void *) w->rf);

	ws_start(w->ws);

	return w;
}
