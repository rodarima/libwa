#include "chat.h"

#include <uthash.h>
#include <utlist.h>
#include "wa.h"


/* Sorted in chronological order */
typedef struct conv_msg_t
{
	priv_msg_t *pm;

	struct conv_msg_t *prev, *next;
} conv_msg_t;

typedef struct conv_t
{
	conv_msg_t *l;
	UT_hash_handle hh;
} conv_t;

typedef struct
{
	conv_t *conv;
} chat_t;

conv_t *
get_conv(chat_t *chat, char *jid)
{
	conv_t *conv;
	conv_msg_t *cm;

	HASH_FIND_STR(chat->conv, pm->jid, conv);

	if(!conv)
	{
		conv = calloc(sizeof(conv_t), 1);
		HASH_ADD_KEYPTR(hh, chat->conv, pm->jid, strlen(pm->jid), conv);
	}

	cm = malloc(sizeof(conv_msg_t));
	cm->pm = pm;

	return 0;
}

int
chat_recv_last_priv_msg(chat_t *chat, priv_msg_t *pm)
{
	conv_t *conv;
	conv_msg_t *cm;

	conv = get_conv(chat, pm->jid);

	cm = malloc(sizeof(conv_msg_t));
	cm->pm = pm;

	/* Insert the message at the end of the conversation */
	DL_APPEND(conv->l, cm);

	return 0;
}

int
chat_recv_before_priv_msg(chat_t *chat, priv_msg_t *pm)
{
	conv_t *conv;
	conv_msg_t *cm;

	conv = get_conv(chat, pm->jid);

	cm = malloc(sizeof(conv_msg_t));
	cm->pm = pm;

	/* Insert the message at the start of the conversation */
	DL_PREPEND(conv->l, cm);

	return 0;
}
