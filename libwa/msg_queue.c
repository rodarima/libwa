#include "msg_queue.h"

#include <utlist.h>

mq_t *
mq_init()
{
	mq_t *mq;

	mq = malloc(sizeof(mq_t));

	/* Empty queue */
	mq->q = NULL;

	return mq;
}

int
mq_bnode_push(mq_t *mq, bnode_t *bn)
{
	/* TODO: Check that it is not in the queue */

	mq_node_t *node;

	node = malloc(sizeof(mq_node_t));

	node->ptr = bn;

	DL_APPEND(mq->q, node);

	return 0;
}

bnode_t *
mq_bnode_pop(mq_t *mq)
{
	mq_node_t *node, *tmp;
	bnode_t *bn = NULL;;

	DL_FOREACH_SAFE(mq->q, node, tmp)
	{
		DL_DELETE(mq->q, node);
		bn = node->ptr;
		free(node);
		break;
	}

	return bn;
}
