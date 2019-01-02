#pragma once

#include <uthash.h>

#include "bnode.h"

typedef struct mq_node_t
{
	void *ptr;

	struct mq_node_t *next, *prev;

} mq_node_t;

typedef struct
{
	mq_node_t *q;
} mq_t;

mq_t *
mq_init();

int
mq_bnode_push(mq_t *mq, bnode_t *bn);

bnode_t *
mq_bnode_pop(mq_t *mq);

//#define MQ_ITER(mq, node, tmp) HASH_ITER(hh, mq->q, node, tmp)

