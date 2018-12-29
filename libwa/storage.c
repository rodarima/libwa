#include "storage.h"

#include <string.h>
#include <json-c/json.h>
#include <linux/limits.h>

static int
path_from_key(store_t *s, char *buf, const char *key)
{
	strcpy(buf, s->path);
	strcat(buf, "/");
	strcat(buf, key);
	strcat(buf, ".json");

	return 0;
}

store_t *
storage_init(const char *path)
{
	store_t *s;

	s = malloc(sizeof(store_t));
	s->path = path;

	return s;
}

void
storage_free(store_t *s)
{
	free(s);
}

int
storage_read(store_t *s, const char *key, json_object **obj)
{
	char path[PATH_MAX];
	json_object *root;

	path_from_key(s, path, key);
	root = json_object_from_file(path);

	if(!root)
		return -1;

	*obj = root;

	return 0;
}

int
storage_write(store_t *s, const char *key, json_object *obj)
{
	char path[PATH_MAX];

	path_from_key(s, path, key);
	return json_object_to_file(path, obj);
}
