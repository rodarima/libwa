#pragma once

#include <uthash.h>

#include "bnode.h"

typedef struct {
	char *name;
	char *notify;
	char *jid;

	UT_hash_handle hh;
} user_t;

typedef struct {
	char *text;
	user_t *from;
	user_t *to;
} priv_msg_t;

typedef struct {
	user_t *users;
	user_t *me;

	/* Callbacks */

	int (*priv_msg_cb)(void *, priv_msg_t *);
	void *priv_msg_ptr;

	int (*update_user_cb)(void *, user_t *);
	void *update_user_ptr;

} session_t;

session_t *
session_init();

int
session_cb_priv_msg(session_t *s, void *priv_msg_ptr,
		int (*priv_msg_cb)(void *, priv_msg_t *));

int
session_cb_update_user(session_t *s, void *update_user_ptr,
		int (*update_user_cb)(void *, user_t *));


int
session_recv_priv_msg(session_t *s, priv_msg_t *pm);

user_t *
session_find_user(session_t *s, const char *jid);


int
session_recv_bnode(session_t *s, bnode_t *bn);
