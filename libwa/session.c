#include "session.h"

#include <assert.h>
#include <string.h>

#include "wa.h"
#include "qr.h"
#include "storage.h"

#define DEBUG LOG_LEVEL_INFO
#include "log.h"

#define SESSION_KEY "session"

int
session_update_user(wa_t *w, user_t *u)
{
	user_t *f;
	cb_t *cb;

	assert(u->jid);

	LOG_DEBUG("Updating user %s (%s)\n", u->name, u->jid);

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
		free(u);
		u = f;
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

	/* User u not freed here */

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
update_last_forwarded(wa_t *wa, uint64_t timestamp)
{
	json_object *root, *v;

	root = json_object_new_object();
	v = json_object_new_int(timestamp);
	json_object_object_add(root, "timestamp", v);

	storage_write(wa->s, "last_forwarded", root);

	json_object_put(root);
	return 0;
}

int
session_recv_priv_msg(wa_t *w, priv_msg_t *pm)
{
	int ret = 0;
	cb_t *cb;

	cb = w->cb;

	if(cb->priv_msg)
	{
		ret = cb->priv_msg(cb->ptr, pm);
	}

	/* Ignore by now */
//	update_last_forwarded(w, pm->timestamp);

	return ret;
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
	json_object *root, *v;

	if(storage_read(wa->s, SESSION_KEY, &root))
	{
		return -1;
	}

	v = json_object_object_get(root, "client_token");
	wa->client_token = strdup(json_object_get_string(v));
	v = json_object_object_get(root, "server_token");
	wa->server_token = strdup(json_object_get_string(v));
	v = json_object_object_get(root, "browser_token");
	wa->browser_token = strdup(json_object_get_string(v));
	v = json_object_object_get(root, "client_id");
	wa->client_id = strdup(json_object_get_string(v));

	v = json_object_object_get(root, "crypto");
	crypto_restore(wa->c, v);

	json_object_put(root);

	if(storage_read(wa->s, "last_forwarded", &root))
	{
		/* Simply use 0 as timestamp */
		wa->last_forwarded = 0;
		return 0;
	}

	v = json_object_object_get(root, "timestamp");
	wa->last_forwarded = json_object_get_int64(v);

	json_object_put(root);

	return 0;
}

int
session_save(wa_t *wa)
{
	json_object *root, *v;
	root = json_object_new_object();
	v = json_object_new_string(wa->client_token);
	json_object_object_add(root, "client_token", v);
	v = json_object_new_string(wa->server_token);
	json_object_object_add(root, "server_token", v);
	v = json_object_new_string(wa->browser_token);
	json_object_object_add(root, "browser_token", v);
	v = json_object_new_string(wa->client_id);
	json_object_object_add(root, "client_id", v);

	v = crypto_save(wa->c);
	json_object_object_add(root, "crypto", v);

	if(storage_write(wa->s, SESSION_KEY, root))
	{
		return -1;
	}

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
