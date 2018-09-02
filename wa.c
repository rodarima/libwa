#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>
#include <libwebsockets.h>

#define WA_WEB_VERSION "[0,3,557]"
#define WA_WEB_CLIENT "[\"libwa\",\"Chromium\"]"

#include "wa.h"
#include "ws.h"

#include <json-c/json.h>

void qr_encode(char *s);

char* b64_encode(char* buf, size_t len)
{
	BIO *b64, *mem;
	BUF_MEM *bptr;
	char *buff;

	// Shit, this base64 thing with openssl was hard to get right.

	b64 = BIO_new(BIO_f_base64());
	mem = BIO_new(BIO_s_mem());

	// No b64 newlines.
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	b64 = BIO_push(b64, mem);

	BIO_write(b64, buf, len);
	BIO_flush(b64);

	BIO_get_mem_ptr(b64, &bptr);

	buff = (char *) malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}

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

	len = snprintf(buf, 1024, "%s,%s,%s", w->ref, "thisisthekeeey", w->client_id);
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
	struct recv_filter *rf = malloc(sizeof(*rf));

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
	if(msg->tag) free(msg->tag);
	if(msg->cmd) free(msg->cmd);
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

int wa_buf_to_msg(char *buf, struct wa_msg **msg_ptr)
{
	char *tag, *cmd, *sep;

	sep = strchr(buf, ',');
	*sep = '\0';
	tag = strdup(buf);
	cmd = strdup(sep + 1);

	struct wa_msg *msg = malloc(sizeof(*msg));
	msg->tag = tag;
	msg->cmd = cmd;

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
	struct tag_filter **p = &rf->tf;

	tf->tag = tag;
	tf->next = NULL;
	tf->cond = malloc(sizeof(*(tf->cond)));

	pthread_cond_init(tf->cond, NULL);

	pthread_mutex_lock(rf->lock);

	while (*p) *p = (*p)->next;
	*p = tf;

	pthread_mutex_unlock(rf->lock);

	return tf;
}


int wa_recv_cb(struct recv_filter *rf, struct wa_msg *msg)
{
	pthread_mutex_lock(rf->lock);

	struct tag_filter **p = &rf->tf;
	int found = 0;

	fprintf(stderr, "%s: received msg tag:%s\n", __func__, msg->tag);
	while (*p)
	{
		// Tag found?
		fprintf(stderr, "%s: looking for tag:%s\n", __func__, (*p)->tag);
		if(strcmp(msg->tag, (*p)->tag) == 0)
		{
			//Remove from filter and signal
			(*p)->msg = msg;
			pthread_cond_signal((*p)->cond);
			fprintf(stderr, "ACCEPTED: tag:%s cmd:%s\n",
				       msg->tag, msg->cmd);
			found = 1;
			*p = (*p)->next;
			break;
		}
		p = &(*p)->next;
	}

	if (!found)
	{
		//Drop
		fprintf(stderr, "DROP: %s\n", msg->cmd);
	}

	pthread_mutex_unlock(rf->lock);

	return found;
}


void wa_recv_buf_cb(void *user, void *data, size_t len)
{
	struct recv_filter *rf = (struct recv_filter *) user;
	char *buf = (char *) data;
	struct wa_msg *msg;

	wa_buf_to_msg(buf, &msg);

	if (!wa_recv_cb(rf, msg))
		wa_msg_free(msg);
}

struct wa *wa_init()
{
	struct wa *w = malloc(sizeof(struct wa));
	memset(w, sizeof(struct wa), 0);


	w->rf = wa_recv_filter_init();
	w->ws = ws_init();

	ws_register_recv_cb(w->ws, wa_recv_buf_cb, (void *) w->rf);

	ws_start(w->ws);

	return w;
}
