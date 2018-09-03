#ifndef _WA_H_
#define _WA_H_

#include <openssl/evp.h>
#include <pthread.h>

#define MAX_QUEUE 10

struct wa_msg
{
	char *tag;
	char *cmd;
};

struct tag_filter
{
	char *tag;
	pthread_cond_t *cond;
	struct wa_msg *msg;
	struct tag_filter *next;
};

struct recv_filter
{
	struct tag_filter *tf;
	pthread_mutex_t *lock;
	pthread_cond_t *cond;
	struct wa_msg *msg;

	/* For receiving multiple frames */
	size_t buf_size;
	char *buf;
	char *ptr;

	struct wa_msg *queue[MAX_QUEUE];
	int queue_index;
};

struct wa
{
	char *client_id;
	char *ref;
	EVP_PKEY *keypair;
	char *pubkey;
	struct recv_filter *rf;
	struct ws *ws;
};

struct wa *wa_init();
int wa_login(struct wa *w);
void wa_free(struct wa *w);
void wa_loop(struct wa *w);
struct wa_msg *wa_request(struct wa *w, struct wa_msg *msg);
void wa_msg_free(struct wa_msg *msg);
struct tag_filter *wa_filter_add(struct recv_filter *rf, char *tag);

#endif
