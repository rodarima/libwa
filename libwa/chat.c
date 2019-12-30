#include "chat.h"

#include <uthash.h>
#include <utlist.h>
#include "wa.h"
#include "session.h"

#define DEBUG LOG_LEVEL_INFO
#include "log.h"

chat_t *
chat_init()
{
	chat_t *c;

	c = calloc(1, sizeof(chat_t));

	return c;
}

static conv_t *
get_conv(wa_t *wa, char *jid)
{
	conv_t *conv;
	chat_t *chat;

	chat = wa->chat;

	HASH_FIND_STR(chat->conv, jid, conv);

	if(!conv)
	{
		conv = calloc(sizeof(conv_t), 1);

		/* This may be null if we didn't receive any messages yet */
		conv->last_msg_id = storage_user_read(wa->s, jid, "last");
		conv->jid = jid;

		HASH_ADD_KEYPTR(hh, chat->conv, jid, strlen(jid), conv);
		LOG_DEBUG("New chat created: jid:%s\n", jid);
	}

	return conv;
}

static int
cmp_conv_msg(conv_msg_t *a, conv_msg_t *b)
{
	time_t ta, tb;

	ta = a->pm->timestamp;
	tb = b->pm->timestamp;

	return (ta > tb) ? 1 : ((ta < tb) ? -1 : 0);
}

int
chat_update(wa_t *wa, char *jid, int count)
{
	conv_t *conv;

	conv = get_conv(wa, jid);

	conv->count = count;

	return 0;
}

int
chat_recv_priv_msg(wa_t *wa, priv_msg_t *pm)
{
	conv_t *conv;
	conv_msg_t *cm;

	conv = get_conv(wa, pm->jid);

	cm = malloc(sizeof(conv_msg_t));
	cm->pm = pm;

	DL_INSERT_INORDER(conv->l, cm, cmp_conv_msg);

	if(!conv->last_msg_id)
		return 0;

	LOG_DEBUG("Last:%s msg_ig:%s\n", conv->last_msg_id, pm->msg_id);

	if(strcmp(conv->last_msg_id, pm->msg_id) != 0)
		return 0;

	/* This message is the last forwarded to the client */
	conv->last = cm;

	return 0;
}

int
clean_conv(conv_t *conv)
{
	conv_msg_t *cm, *tmp;

	if(!conv->last)
		return 0;

	DL_FOREACH_SAFE(conv->l, cm, tmp)
	{
		DL_DELETE(conv->l, cm);
		free(cm);

		if(conv->last == cm)
			break;
	}

	conv->last = NULL;

	return 0;
}

int
chat_flush_conv(wa_t *wa, conv_t *conv)
{
	conv_msg_t *cm, *tmp;

	clean_conv(conv);

	/* Don't continue if there are no more messages */
	if(!conv->l)
		return 0;

	DL_FOREACH_SAFE(conv->l, cm, tmp)
	{
		conv->last_msg_id = cm->pm->msg_id;
		session_recv_priv_msg(wa, cm->pm);
		DL_DELETE(conv->l, cm);
		free(cm);
	}

	if(conv->last_msg_id)
		storage_user_write(wa->s, conv->jid, "last", conv->last_msg_id);

	return 0;
}

int
chat_flush_jid(wa_t *wa, char *jid)
{
	conv_t *conv;

	conv = get_conv(wa, jid);
	return chat_flush_conv(wa, conv);
}

int
chat_flush(wa_t *wa)
{
	chat_t *chat;
	conv_t *conv, *tmp;

	chat = wa->chat;

	LOG_DEBUG("Flushing all chats\n");

	HASH_ITER(hh, chat->conv, conv, tmp)
	{
		chat_flush_conv(wa, conv);
	}

	return 0;
}

