#define _GNU_SOURCE
#include <stdio.h>
#include <json-c/json.h>

#include "l1.h" /* For metric and flag... FIXME */
#include "l2.h"
#include "l3.h"

#include "wa.h"
#include "bnode.h"
#include "session.h"
#include "l4.h"

#define DEBUG LOG_LEVEL_DEBUG
#include "log.h"

int
l3_recv_bnode(wa_t *wa, bnode_t *bn);

int
l3_recv_message(wa_t *wa, bnode_t *bn);

int
l3_recv_contact(wa_t *wa, bnode_t *bn)
{
	json_object *j;
	user_t *u;
	char *jid, *notify, *name;

	if(!bn->desc)
		return 1;

	if(strcmp(bn->desc, "user") != 0)
		return 1;

	if(!bn->attr)
		return 1;

	j = json_object_object_get(bn->attr, "jid");
	if(!j)
		return 1;

	jid = strdup(json_object_get_string(j));

	j = json_object_object_get(bn->attr, "short");
	if(!j)
		return 1;

	notify = strdup(json_object_get_string(j));

	j = json_object_object_get(bn->attr, "name");
	if(!j)
		return 1;

	name = strdup(json_object_get_string(j));

	u = malloc(sizeof(user_t));
	assert(u);
	u->name = name;
	u->notify = notify;
	u->jid = jid;

	/* FIXME: The user u is freed inside session_update_user */
	session_update_user(wa, u);

	return 0;
}

int
l3_check_queue(wa_t *wa)
{
	bnode_t *bn, *begin = NULL;
	int stop = 0;

	while(!stop)
	{
		stop = 1;
		while((bn = mq_bnode_pop(wa->mq)))
		{
			if(bn == begin)
				/* Loop detected */
				break;

			if(!begin)
				begin = bn;

			if(!l3_recv_bnode(wa, bn))
			{
				stop = 0;
				begin = NULL;
			}
		}
	}
	return 0;
}

int
l3_recv_contacts(wa_t *wa, bnode_t *bn)
{
	int i, ret=0;
	json_object *jval;
	const char *val;

	if(bn->type != BNODE_LIST)
		return -1;

	if(!bn->data.list)
		return -1;

	if(bn->attr)
	{
		jval = json_object_object_get(bn->attr, "type");
		if(jval)
		{
			val = json_object_get_string(jval);
			assert(val);

			if(strcmp(val, "frequent") == 0)
			{
				LOG_INFO("Ignoring frequent contact list\n");
				return 0;
			}
		}
	}


	for(i=0; i<bn->len; i++)
	{
		ret |= l3_recv_contact(wa, bn->data.list[i]);
	}

	LOG_WARN(" ----- CONTACTS RECEIVED! ----- \n");
	wa->state = WA_STATE_CONTACTS_RECEIVED;

	/* As we update the state, some msg can be dequeued */
	l3_check_queue(wa);

	return ret;
}

int
l3_recv_response(wa_t *wa, bnode_t *bn)
{
	json_object *jtype;
	const char *type;
	int ret;

	if(!bn->attr)
		return 1;

	jtype = json_object_object_get(bn->attr, "type");

	if(!jtype)
		return 1;

	type = json_object_get_string(jtype);
	assert(type);

	if(strcmp(type, "contacts") == 0)
	{
		/* On the reception of the contact list, we assume the state is
		 * ready to any further operation */
		ret = l3_recv_contacts(wa, bn);

		return ret;
	}

	/* Unknown response msg */

	return 0;
}

int
l3_recv_action_child(wa_t *wa, bnode_t *bn)
{
	if(strcmp("contacts", bn->desc) == 0)
		return l3_recv_contacts(wa, bn);
	else if(strcmp("message", bn->desc) == 0)
		return l3_recv_message(wa, bn);

	return -1;
}

int
action_filter(wa_t *wa, bnode_t *bn)
{
	/* No need to queue if we already have the before part */

	LOG_INFO("wa->state = %d\n", wa->state);
	if(wa->state >= WA_STATE_BEFORE_RECEIVED)
		return 0;

	if(bnode_attr_exists(bn, "add", "last"))
	{
		mq_bnode_push(wa->mq, bn);
		return 1;
	}

	if(wa->state >= WA_STATE_CONTACTS_RECEIVED)
		return 0;

	if(bnode_attr_exists(bn, "add", "before"))
	{
		mq_bnode_push(wa->mq, bn);
		return 1;
	}

	return 0;
}

int
l3_recv_action(wa_t *wa, bnode_t *bn)
{
	int i, ret = 0;
	bnode_t *child;

//	if(action_filter(wa, bn))
//	{
//		LOG_WARN("bnode queued\n");
//		return 1;
//	}

	if(bn->type == BNODE_LIST)
	{
		for(i=0; i<bn->len; i++)
		{
			child = (bnode_t *) bn->data.list[i];
			ret |= l3_recv_action_child(wa, child);
		}
	}
	if(bnode_attr_exists(bn, "add", "before"))
	{
		wa->state = WA_STATE_BEFORE_RECEIVED;
	}

	if(bnode_attr_exists(bn, "add", "last"))
	{
		wa->state = WA_STATE_LAST_RECEIVED;
		wa->state = WA_STATE_READY;
	}

	return ret;
}

int
l3_recv_message(wa_t *wa, bnode_t *bn)
{

	if(wa->state != WA_STATE_CONTACTS_RECEIVED)
	{
		/* Queue the message until the contacts are received */
		//mq_add_bnode();
	}
	//LOG_INFO("Received msg bnode:\n");
	//bnode_print(bn, 0);
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
		LOG_WARN("Unknown contact type: %s\n", type);
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


/* We have an order problem with the three packets that arrive at the beginning
 * of the connection, sometimes out of order:
 *
 * a) <action:message add:last> is received with the last message in
 * each recent conversation.
 *
 * b) <action:contacts> contains all the contact list.
 *
 * c) <action:message add:before last:true> contains the last ~20 messages of
 * each conversation, *excluding the last one*.
 *
 * This behavior leads to the need of queueing the packets, as we want to read
 * (b), then (c) then (a), so we have all the contacts before reading the
 * messages.
 *
 * Also, we don't know which packet is which until we decrypt and parse each of
 * them. Thus, we need to queue them *after* the parsing process.
 */

int
l3_recv_bnode(wa_t *wa, bnode_t *bn)
{

	if(!bn->desc)
	{
		LOG_WARN("desc is NULL\n");
		return -1;
	}
	bnode_summary(bn, 0);
	if(strcmp("action", bn->desc) == 0)
		return l3_recv_action(wa, bn);
	else if(strcmp("response", bn->desc) == 0)
		return l3_recv_response(wa, bn);
	else
	{
		LOG_WARN("Unknown bnode with desc: %s\n", bn->desc);
	}

	return 0;
}

int
l3_recv_msg(wa_t *wa, msg_t *msg)
{
	bnode_t *bn_l3;
	buf_t *buf;
	int ret;

	buf = malloc(sizeof(buf_t));
	assert(buf);
	buf->ptr = msg->cmd;
	buf->len = msg->len;

	bn_l3 = bnode_from_buf(buf);

	free(buf);


	//LOG_DEBUG("Received msg at l3, bnode is:\n");
	//bnode_print(bn_l3, 0);

	ret = l3_recv_bnode(wa, bn_l3);

	/* TODO: Free the bnode when we know is needed */
	//bnode_free(bn_l3);

	return ret;
}

int
l3_send_relay(wa_t *wa, bnode_t *child, char *tag)
{
	bnode_t *b;
	int ret;
	buf_t *out;
	char *msg_counter;

	b = malloc(sizeof(bnode_t));
	assert(b);

	b->desc = strdup("action");
	b->attr = json_object_new_object();

	json_object_object_add(b->attr, "type",
			json_object_new_string("relay"));

	asprintf(&msg_counter, "%d", wa->msg_counter++);
	json_object_object_add(b->attr, "epoch",
			json_object_new_string(msg_counter));

	b->type = BNODE_LIST;
	b->data.list = (bnode_t **) malloc(sizeof(bnode_t *) * 1);
	b->len = 1;

	b->data.list[0] = child;

	out = bnode_to_buf(b);

	ret = l2_send_buf(wa, out, tag, METRIC_MESSAGE, FLAG_IGNORE);

	free(b);
	/*free(buf); Not here */
	free(out);
	free(msg_counter);

	return ret;
}

int
l3_send_relay_msg(wa_t *wa, buf_t *buf, char *tag)
{
	bnode_t *b;
	int ret;

	b = malloc(sizeof(bnode_t));
	assert(b);

	b->desc = strdup("message");
	b->attr = NULL;

	b->type = BNODE_BINARY;
	b->data.bytes = buf->ptr;
	b->len = buf->len;

	ret = l3_send_relay(wa, b, tag);

	free(b);

	return ret;
}

int
l3_send_seen(wa_t *wa, char *jid, char *id)
{
	/* Send the following:
	 *
	 * metric = 11
	 * flag = 0xc0
	 *
	 * BNODE
	 * {
	 *   desc: action
	 *   type: list
	 *   attr:
	 *   {
	 *     type : set
	 *     epoch : 6 (Incremental msg counter)
	 *   }
	 *   content
	 *   {
	 *     BNODE
	 *     {
	 *       desc: read
	 *       type: empty
	 *       attr:
	 *       {
	 *         jid : 34666666666@s.whatsapp.net (The sender)
	 *         index : XXXXXXXXXXXXXXXXXXXXXXXXXXXXX (The last msg id)
	 *         owner : false (If the msg comes from us)
	 *         count : 2 (Number of messages seen)
	 *       }
	 *       content: empty
	 *     }
	 * }
	 * */

	bnode_t *root, *child;
	int ret;
	char *epoch;
	int metric, flags;
	buf_t *out;

	asprintf(&epoch, "%d", wa->msg_counter++);

	root = calloc(sizeof(bnode_t), 1);
	assert(root);

	root->desc = strdup("action");

	bnode_attr_add(root, "type", "set");
	bnode_attr_add(root, "epoch", epoch);

	root->type = BNODE_LIST;
	root->data.list = malloc(sizeof(bnode_t *) * 1);
	root->len = 1;

	child = calloc(sizeof(bnode_t), 1);

	child->desc = strdup("read");
	child->type = BNODE_EMPTY;

	bnode_attr_add(child, "jid", jid);
	bnode_attr_add(child, "index", id);
	bnode_attr_add(child, "owner", "false");

	/* TODO: Implement count > 1 */

	bnode_attr_add(child, "count", "1");

	root->data.list[0] = child;

	out = bnode_to_buf(root);

	metric = METRIC_READ;

	/* Original flags:
	 *
	 * flags = FLAG_EXPIRES | FLAG_SKIP_OFFLINE;
	 *
	 * But we want an ack to proceed.
	 */

	flags = FLAG_EXPIRES | FLAG_ACK_REQUEST;

	LOG_INFO("Sending seen of msg %s to %s\n", id, jid);

	ret = l2_send_buf(wa, out, NULL, metric, flags);

	bnode_free(root);

	/* The child is automatically free'd */
	free(epoch);


	return ret;
}
