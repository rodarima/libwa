#include "session.h"

#define DEBUG LOG_LEVEL_INFO
#include "log.h"
#include "wa.h"
#include "qr.h"

#include <assert.h>
#include <string.h>

int
session_update_user(wa_t *w, user_t *u)
{
	user_t *f;
	cb_t *cb;

	assert(u->jid);

	LOG_INFO("Updating user %s (%s)\n", u->name, u->jid);

	HASH_FIND_STR(w->users, u->jid, f);

	if(f)
	{
		assert(strcmp(f->jid, u->jid) == 0);

		free(f->name);
		free(f->notify);
		free(f->jid);

		f->name = u->name;
		f->notify = u->notify;
		f->jid = u->jid;
	}
	else
	{
		HASH_ADD_KEYPTR(hh, w->users, u->jid, strlen(u->jid), u);
	}

	cb = w->cb;

	if(cb->update_user)
	{
		return cb->update_user(cb->ptr, u);
	}

	return 0;
}

user_t *
session_find_user(wa_t *w, const char *jid)
{
	user_t *u;
	HASH_FIND_STR(w->users, jid, u);
	return u;
}

int
session_recv_priv_msg(wa_t *w, priv_msg_t *pm)
{
	cb_t *cb;

	cb = w->cb;

	if(cb->priv_msg)
	{
		return cb->priv_msg(cb->ptr, pm);
	}

	return 0;
}

static char*
generate_qr_data(wa_t *wa)
{
	char *data;
	int len;
	char *pubkey = crypto_get_pub_client(wa->c);

	len = strlen(wa->ref) + 1 +
		strlen(pubkey) + 1 +
		strlen(wa->client_id) + 1;

	data = malloc(len);

	strcpy(data, wa->ref);
	strcat(data, ",");
	strcat(data, pubkey);
	strcat(data, ",");
	strcat(data, wa->client_id);

	return data;
}

int
session_restore(wa_t *wa)
{
	return 1;

	return 0;
}

int
session_new(wa_t *wa)
{
	char *data;

	/* Generate a QR and wait for the reply */
	data = generate_qr_data(wa);

	assert(data);

	qr_print(data);

	return 0;
}
