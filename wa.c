#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>
#include <libwebsockets.h>
#include <uthash.h>
#include <assert.h>

#define WA_WEB_VERSION "[0,3,557]"
#define WA_WEB_CLIENT "[\"libwa\",\"Chromium\"]"

#include "wa.h"
#include "crypto.h"


#include <json-c/json.h>

void qr_encode(char *s);

static char *
generate_client_id()
{
	//b = secrets.token_bytes(16)
	//b64 = base64.b64encode(b)
	//return b64.decode()

#define RND_BYTES 16
	char buf[RND_BYTES], *client_id;
	if(RAND_bytes((unsigned char *)buf, RND_BYTES) <= 0)
	{
		return NULL;
	}

	client_id = b64_encode(buf, RND_BYTES);

	return client_id;

#undef RND_BYTES
}

int
generate_QR(wa_t *wa)
{
	char buf[1024];
	int len;

	len = snprintf(buf, 1024, "%s,%s,%s", wa->ref, wa->pubkey, wa->client_id);
	if (len >= 1024)
		return -1;

	qr_encode(buf);
	printf("QR: %s\n", buf);

	return 0;
}

int
wa_action_init(wa_t *wa)
{
#define BUFSIZE 1024

	//char block[LWS_PRE + BUFSIZE];
	msg_t *msg, *res;
	int len;
	const char *ref;
	json_object *jo, *jref;

	if(!wa->client_id)
	{
		fprintf(stderr, "client_id is missing\n");
		return -1;
	}

	msg = malloc(sizeof(*msg));
	msg->cmd = malloc(BUFSIZE);

	len = snprintf(msg->cmd, BUFSIZE,
		"[\"admin\",\"init\",%s,%s,\"%s\",true]",
		WA_WEB_VERSION, WA_WEB_CLIENT, wa->client_id);

	if (len >= BUFSIZE)
	{
		fprintf(stderr, "BUFSIZE too small, aborting\n");
		return -1;
	}

	msg->tag = strdup("init-001");
	msg->len = len;

	res = wa_request(wa, msg);

	fprintf(stderr, "Received cmd:%s\n", (char *) res->cmd);

	/* FIXME: The response is NOT null terminated, so the tokenizer reads
	 * outside the buffer */

	assert(((char *) res->cmd)[res->len] == '\0');

	jo = json_tokener_parse(res->cmd);

	assert(jo);

	jref = json_object_object_get(jo, "ref");

	assert(jref);

	ref = json_object_get_string(jref);

	//json_object_put(jref);

	printf("Got ref:%s\n", ref);
	wa->ref = strdup(ref);

	json_object_put(jo);


	free(msg->tag);
	free(msg->cmd);
	free(msg);

	free(res->tag);
	free(res->cmd);
	free(res);

#undef BUFSIZE

	return 0;
}

void
wa_free(wa_t *w)
{
	if(w->client_id) free(w->client_id);
	free(w);
}

int
wa_restore_session(wa_t *wa)
{
	return 1;

	return 0;
}

int
wa_new_session(wa_t *wa)
{
	/* After the init, a comm message will arrive, hopefully */

	dispatch_wait_reply()

	return 0;
}

int
wa_login(wa_t *wa)
{
	wa->client_id = generate_client_id(wa);
	if(wa_action_init(wa))
	{
		fprintf(stderr, "%s: init failed, aborting login\n",
			       __func__);

		return -1;
	}

	if(wa_restore_session(wa))
	{
		fprintf(stderr, "%s: requesting a new session\n",
			       __func__);

		/* Generate a QR and wait for the reply */
		generate_QR(wa);

		wa_new_session(wa);
	}


	fprintf(stderr, "%s: logged in\n", __func__);

	return 0;
}

int
wa_msg_handle(wa_t *wa, msg_t *msg)
{
	/* Unsolicited message arrived */

	// Try to get json from cmd
	// FIXME: null terminate cmd
	struct json_tokener *tok = json_tokener_new();
	enum json_tokener_error jerr;

	struct json_object *jo = json_tokener_parse_ex(tok, msg->cmd, msg->len);
	jerr = json_tokener_get_error(tok);

	if(jerr != json_tokener_success)
	{
		fprintf(stderr, "Not json, ignoring tag:%s\n", msg->tag);
		// Handle errors, as appropriate for your application.
		return 0;
	}

	if(jo)
		fprintf(stderr, "jo is not NULL\n");

	fprintf(stderr, "A json msg was received: %s\n", (char *) msg->cmd);
	return 0;
}

msg_t *
wa_request(wa_t *wa, msg_t *msg)
{
	fprintf(stderr, "Sending msg:\n\ttag:%s\n\tcmd:%s\n",
		       msg->tag, (char *) msg->cmd);

	return dispatch_request(wa->d, msg);
}

int
wa_keys_init(wa_t *w)
{
	if(generate_keys(&(w->keypair)))
		return -1;

	w->pubkey = get_public_key(w->keypair);
	if(!w->pubkey)
		return -1;

	return 0;
}

void
wa_loop(wa_t *wa)
{
	while(wa->run)
		dispatch_events(wa->d);

	dispatch_end(wa->d);
}

wa_t *
wa_init()
{
	wa_t *wa = calloc(1, sizeof(wa_t));
	wa->run = 1;
	wa_keys_init(wa);

	wa->d = dispatch_init();

	return wa;
}
