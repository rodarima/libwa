#define _GNU_SOURCE

#include "storage.h"

#include <string.h>
#include <stdio.h>

#include <json-c/json.h>
#include <linux/limits.h>

#define DEBUG LOG_LEVEL_INFO
#include "log.h"

#include <string.h>
#include <limits.h>     /* PATH_MAX */
#include <sys/stat.h>   /* mkdir(2) */
#include <errno.h>

/* Creates all the files before the actual file */
int
mkdir_p(char *path)
{
	char *p;

	errno = 0;

	/* Iterate the string */
	for(p = path + 1; *p; p++)
	{
		if(*p == '/')
		{
			/* Temporarily truncate */
			*p = '\0';

			if(mkdir(path, S_IRWXU) != 0)
			{
				if(errno != EEXIST)
					return -1;
			}

			*p = '/';
		}
	}

	return 0;
}


static char *
path_from_key(store_t *s, const char *key)
{
	char *path;

	asprintf(&path, "%s/%s.json", s->path, key);

	return path;
}

/* This function clashes with the bitlbee one called "storage_init", so we add
 * the prefix "wa_". We should use the prefix anyway in all exported
 * functions... */
store_t *
wa_storage_init(const char *path)
{
	store_t *s;

	s = malloc(sizeof(store_t));
	s->path = strdup(path);

	LOG_INFO("s->path is now %s\n", s->path);

	return s;
}

void
storage_free(store_t *s)
{
	free(s->path);
	free(s);
}

int
storage_read(store_t *s, const char *key, json_object **obj)
{
	char *path;
	json_object *root;

	LOG_INFO("path = %s\n", s->path);

	path = path_from_key(s, key);
	root = json_object_from_file(path);

	if(!root)
		return -1;

	*obj = root;
	free(path);

	return 0;
}

int
storage_write(store_t *s, const char *key, json_object *obj)
{
	char *path;
	int ret = 0;

	path = path_from_key(s, key);
	ret = json_object_to_file(path, obj);
	free(path);

	return ret;
}

int
storage_user_write(store_t *s, char *jid, char *key, char *value)
{
	char *path, *user, *p;
	FILE *f;

	/* Remove server address */

	user = strdup(jid);
	p = strchr(user, '@');

	if(p)
		*p = '\0';

	asprintf(&path, "%s/user/%s/%s", s->path, user, key);

	mkdir_p(path);

	f = fopen(path, "w");
	fprintf(f, "%s", value);
	fclose(f);

	free(path);
	free(user);

	return 0;
}

char *
storage_user_read(store_t *s, char *jid, char *key)
{
	char *path, *user, *p, *line;
	FILE *f;
	size_t len;

	/* Remove server address */

	user = strdup(jid);
	p = strchr(user, '@');

	if(p)
		*p = '\0';

	asprintf(&path, "%s/user/%s/%s", s->path, user, key);

	f = fopen(path, "w");
	if(!f)
		return NULL;

	getline(&line, &len, f);
	fclose(f);

	free(path);
	free(user);

	return line;
}
