#include "l3.h"

#include "wa.h"
#include "bnode.h"
#include "session.h"
#include "l4.h"
#include "log.h"

int
l3_recv_bnode(wa_t *wa, bnode_t *bn);

int
l3_recv_contact(wa_t *wa, bnode_t *bn)
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

	session_update_user(wa, u);

	return 0;
}

int
l3_recv_contacts(wa_t *wa, bnode_t *bn)
{
	int i, ret=0;

	if(bn->type != BNODE_LIST)
		return 1;

	if(!bn->data.list)
		return 1;

	for(i=0; i<bn->len; i++)
	{
		ret |= l3_recv_contact(wa, bn->data.list[i]);
	}

	return ret;
}

int
l3_recv_response(wa_t *wa, bnode_t *bn)
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
		return l3_recv_contacts(wa, bn);
	}

	/* Unknown response msg */

	return 0;
}

int
l3_recv_action(wa_t *wa, bnode_t *bn)
{
	int i, ret = 0;
	bnode_t *child;

	if(bn->type == BNODE_LIST)
	{
		for(i=0; i<bn->len; i++)
		{
			child = (bnode_t *) bn->data.list[i];
			ret |= l3_recv_bnode(wa, child);
		}
	}
	return ret;
}

int
l3_recv_message(wa_t *wa, bnode_t *bn)
{
	return l4_recv_msg(wa, bn->data.bytes, bn->len);
}

int
l3_recv_frequent_contact(wa_t *wa, bnode_t *bn)
{
	return 0; //TODO session_update_user(wa, u);
}

int
l3_recv_frequent_contacts(wa_t *wa, bnode_t *bn)
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
		ret |= l3_recv_frequent_contact(wa, bn);
	}

	return ret;
}

int
l3_recv_bnode(wa_t *wa, bnode_t *bn)
{
	if(!bn->desc)
	{
		LOG_ERR("desc is NULL\n");
		return -1;
	}
	LOG_INFO("Received bnode with description: %s\n", bn->desc);
	if(strcmp("action", bn->desc) == 0)
		return l3_recv_action(wa, bn);
	else if(strcmp("response", bn->desc) == 0)
		return l3_recv_response(wa, bn);
	else if(strcmp("message", bn->desc) == 0)
		return l3_recv_message(wa, bn);
	else if(strcmp("contacts", bn->desc) == 0)
		return l3_recv_contacts(wa, bn);
	else
	{
		LOG_WARN("Unknown bnode with desc: %s\n", bn->desc);
	}

	return 0;
}

int
l3_recv_msg(wa_t *wa, msg_t *msg_l2)
{
	bnode_t *bn_l3;
	bn_l3 = bnode_parse_msg(msg_l2);

	return l3_recv_bnode(wa, bn_l3);
}
