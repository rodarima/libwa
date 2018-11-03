#include "session.h"
#include "pmsg.h"

#define DEBUG LOG_LEVEL_INFO

#include "log.h"

int
handle(session_t *s, bnode_t *bn);

session_t *
session_init()
{
	session_t *s = malloc(sizeof(session_t));
	assert(s);

	s->users = NULL;
	s->me = malloc(sizeof(user_t));
	assert(s->me);

	s->me->name = "<me>";
	s->me->jid = "my jid";
	s->me->notify = "notify?";

	return s;
}

int
session_update_user(session_t *s, user_t *u)
{
	user_t *f;

	assert(u->jid);

	LOG_INFO("Updating user %s (%s)\n", u->name, u->jid);

	HASH_FIND_STR(s->users, u->jid, f);

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
		HASH_ADD_KEYPTR(hh, s->users, u->jid, strlen(u->jid), u);
	}

	if(s->update_user_cb)
	{
		return s->update_user_cb(s->update_user_ptr, u);
	}

	return 0;
}

user_t *
session_find_user(session_t *s, const char *jid)
{
	user_t *u;
	HASH_FIND_STR(s->users, jid, u);
	return u;
}

int
session_recv_priv_msg(session_t *s, priv_msg_t *pm)
{
	if(s->priv_msg_cb)
	{
		return s->priv_msg_cb(s->priv_msg_ptr, pm);
	}

	return 0;
}


int
session_cb_priv_msg(session_t *s, void *priv_msg_ptr,
		int (*priv_msg_cb)(void *, priv_msg_t *))
{
	s->priv_msg_cb = priv_msg_cb;
	s->priv_msg_ptr = priv_msg_ptr;
	return 0;
}

int
session_cb_update_user(session_t *s, void *update_user_ptr,
		int (*update_user_cb)(void *, user_t *))
{
	s->update_user_cb = update_user_cb;
	s->update_user_ptr = update_user_ptr;
	return 0;
}

int
handle_response_contact(session_t *s, bnode_t *bn)
{
	json_object *j;
	user_t *u;

	u = malloc(sizeof(user_t));
	assert(u);

	if(!bn->desc)
		return 1;

	if(strcmp(bn->desc, "user") != 0)
		return 1;

	if(!bn->attr)
		return 1;

	j = json_object_object_get(bn->attr, "jid");
	if(!j)
		return 1;

	u->jid = strdup(json_object_get_string(j));

	j = json_object_object_get(bn->attr, "short");
	if(!j)
		return 1;

	u->notify = strdup(json_object_get_string(j));

	j = json_object_object_get(bn->attr, "name");
	if(!j)
		return 1;

	u->name = strdup(json_object_get_string(j));

	session_update_user(s, u);

	return 0;
}

int
handle_response_contacts(session_t *s, bnode_t *bn)
{
	int i, ret=0;

	if(bn->type != BNODE_LIST)
		return 1;

	if(!bn->data.list)
		return 1;

	for(i=0; i<bn->len; i++)
	{
		ret |= handle_response_contact(s, bn->data.list[i]);
	}

	return ret;
}

int
handle_response(session_t *s, bnode_t *bn)
{
	json_object *jtype;
	const char *type;

	if(!bn->attr)
		return 1;

	jtype = json_object_object_get(bn->attr, "type");

	if(!jtype)
		return 1;

	type = json_object_get_string(jtype);
	assert(type);

	if(strcmp(type, "contacts") == 0)
	{
		return handle_response_contacts(s, bn);
	}

	/* Unknown response msg */

	return 0;
}

int
handle_action(session_t *s, bnode_t *bn)
{
	int i, ret = 0;
	bnode_t *child;

	if(bn->type == BNODE_LIST)
	{
		for(i=0; i<bn->len; i++)
		{
			child = (bnode_t *) bn->data.list[i];
			ret |= handle(s, child);
		}
	}
	return ret;
}

int
handle_message(session_t *s, bnode_t *bn)
{
	return pmsg_parse_message(s, bn->data.bytes, bn->len);
}

int
handle_frequent_contact(session_t *s, bnode_t *bn)
{
	return 0; //session_update_user(s, u);
}
int
handle_contacts(session_t *s, bnode_t *bn)
{
	user_t *u;
	json_object *j;
	const char *type;
	int i,ret = 0;

	u = malloc(sizeof(user_t));
	assert(u);

	j = json_object_object_get(bn->attr, "type");
	assert(j);
	type = json_object_get_string(j);

	if(strcmp(type, "frequent") != 0)
	{
		LOG_ERR("Unknown contact type: %s\n", type);
		return -1;
	}

	if(bn->type != BNODE_LIST)
		return -1;

	for(i=0; i<bn->len; i++)
	{
		ret |= handle_frequent_contact(s, bn);
	}

	return ret;


}

int
handle(session_t *s, bnode_t *bn)
{
	if(!bn->desc)
	{
		LOG_ERR("desc is NULL\n");
		return -1;
	}
	LOG_INFO("Received bnode with description: %s\n", bn->desc);
	if(strcmp("action", bn->desc) == 0)
		return handle_action(s, bn);
	else if(strcmp("response", bn->desc) == 0)
		return handle_response(s, bn);
	else if(strcmp("message", bn->desc) == 0)
		return handle_message(s, bn);
	else if(strcmp("contacts", bn->desc) == 0)
		return handle_contacts(s, bn);

	return 0;
}

int
session_recv_bnode(session_t *s, bnode_t *bn)
{
	return handle(s, bn);
}
