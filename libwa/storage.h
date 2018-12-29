#pragma once

#include <json-c/json.h>

typedef struct
{
	const char *path;
} store_t;

store_t *
storage_init(const char *path);

void
storage_free(store_t *s);

int
storage_read(store_t *s, const char *key, json_object **obj);

int
storage_write(store_t *s, const char *key, json_object *obj);
