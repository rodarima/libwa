#include "dg.h"
#include "utils.h"
#include "log.h"

#include <errno.h>

dg_t *
dg_init(int src, int dst)
{
	dg_t *dg;

	dg = safe_malloc(sizeof(dg_t));
	dg->src = src;
	dg->dst = dst;
	dg->meta = NULL;
	dg->data = NULL;

	return dg;
}

void
dg_free(dg_t *dg)
{
	if(dg->meta)
	{
		json_object_put(dg->meta);
	}

	free(dg);
}

/* Shortcut */
dg_t *
dg_cmd(int src, int dst, char *cmd)
{
	dg_t *dg;

	dg = dg_init(src, dst);
	
	dg_meta_set(dg, "cmd", cmd);

	return dg;
}

int
dg_meta_set(dg_t *dg, char *key, char *value)
{
	json_object *val_json;

	if(!dg->meta)
	{
		dg->meta = json_object_new_object();

		if(!dg->meta)
		{
			LOG_ERR("Failed to create a new json object\n");
			return 1;
		}
	}

	val_json = json_object_new_string(value);
	json_object_object_add(dg->meta, key, val_json);

	return 0;
}

int
dg_meta_set_int(dg_t *dg, char *key, int value)
{
	json_object *val_json;

	if(!dg->meta)
	{
		dg->meta = json_object_new_object();

		if(!dg->meta)
		{
			LOG_ERR("Failed to create a new json object\n");
			return 1;
		}
	}

	val_json = json_object_new_int(value);
	json_object_object_add(dg->meta, key, val_json);

	return 0;
}

int
dg_meta_get_int(dg_t *dg, char *key, int *value)
{
	json_object *jval;
	int val;

	if(!dg->meta)
	{
		LOG_ERR("The datagram metadata is NULL\n");
		return 1;
	}

	jval = json_object_object_get(dg->meta, key);
	if(!jval)
	{
		/* This may not be a FATAL error */
		LOG_DEBUG("Key not found: %s\n", key);
		return 1;
	}

	errno = 0;
	val = json_object_get_int(jval);

	if(errno)
	{
		LOG_ERR("Failed to obtain value for key: %s\n", key);
		return 1;
	}

	*value = val;

	return 0;
}

char *
dg_meta_get(dg_t *dg, char *key)
{
	json_object *jval;
	const char *val;

	if(!dg->meta)
	{
		LOG_ERR("The datagram metadata is NULL\n");
		return NULL;
	}

	jval = json_object_object_get(dg->meta, key);
	if(!jval)
	{
		/* This may not be a FATAL error */
		LOG_DEBUG("Key not found: %s\n", key);
		return NULL;
	}

	errno = 0;
	val = json_object_get_string(jval);

	if(!val)
	{
		LOG_ERR("Failed to obtain value for key: %s\n", key);
		return NULL;
	}

	return strdup(val);
}

int
dg_msg(dg_t *dg, msg_t *msg)
{
	if(dg->data)
	{
		LOG_ERR("Datagram already has data!");
		return 1;
	}

	/* FIXME: Use safe malloc */
	dg->data = malloc(sizeof(buf_t));
	if(!dg->data)
	{
		LOG_ERR("malloc failed");
		return 1;
	}

	dg->data->ptr = msg->cmd;
	dg->data->len = msg->len;

	return 0;
}
