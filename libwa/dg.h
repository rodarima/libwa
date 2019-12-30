#pragma once

#include <json-c/json.h>
#include "msg.h"
#include "buf.h"

enum { L0=0, L1, L2, L3, L4 };

typedef struct
{
	/* Layer src and dst */
	int src, dst;

	/* Metadata */
	json_object *meta;

	/* Data */
	buf_t *data;

} dg_t; /* dg = DataGram */

dg_t *
dg_init(int src, int dst);

void
dg_free(dg_t *dg);

dg_t *
dg_cmd(int src, int dst, char *cmd);

int
dg_meta_set(dg_t *dg, char *key, char *value);

int
dg_meta_set_int(dg_t *dg, char *key, int value);

int
dg_meta_get_int(dg_t *dg, char *key, int *value);

char *
dg_meta_get(dg_t *dg, char *key);

int
dg_msg(dg_t *dg, msg_t *msg);
