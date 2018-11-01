#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>
#include <libwebsockets.h>
#include <uthash.h>
#include <assert.h>
#include <json-c/json.h>

#define WA_WEB_VERSION "[0,3,1242]"
#define WA_WEB_CLIENT "[\"libwa\",\"Chromium\"]"

#include "wa.h"
#include "crypto.h"
#include "bnode.h"



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

	client_id = crypto_b64_encode(buf, RND_BYTES);

	return client_id;

#undef RND_BYTES
}

int
generate_QR(wa_t *wa)
{
	char buf[1024];
	int len;
	char *pubkey = crypto_get_public_key(wa->c);

	len = snprintf(buf, 1024, "%s,%s,%s", wa->ref, pubkey, wa->client_id);
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
	/* Generate a QR and wait for the reply */
	generate_QR(wa);

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

		wa_new_session(wa);
	}


	fprintf(stderr, "%s: logged in\n", __func__);

	return 0;
}

int
wa_handle_msg_bin(wa_t *wa, msg_t *msg)
{
	msg_t *dec;

	fprintf(stderr, "RECV BIN: tag:%s len:%lu\n", msg->tag, msg->len);
	hexdump(msg->cmd, msg->len);
	fprintf(stderr, "Trying to decrypt...\n");
	dec = crypto_decrypt_msg(wa->c, msg);
	bnode_print_msg(dec);
	return 0;
}

int
wa_update_keys(wa_t *wa, char *secret)
{
	return 0;
}

int
wa_handle_conn(wa_t *wa, struct json_object *array)
{
	struct json_object *arg_obj, *ref_obj;
	const char *ref, *server_tok, *client_tok, *browser_tok, *secret;

	arg_obj = json_object_array_get_idx(array, 1);
	assert(arg_obj);
	assert(json_object_is_type(arg_obj, json_type_object));

	ref_obj = json_object_object_get(arg_obj, "ref");
	assert(ref_obj);
	ref = json_object_get_string(ref_obj);
	assert(ref);

	server_tok = json_object_get_string(
			json_object_object_get(arg_obj, "serverToken"));
	assert(server_tok);
	wa->server_token = strdup(server_tok);

	client_tok = json_object_get_string(
			json_object_object_get(arg_obj, "clientToken"));
	assert(client_tok);
	wa->client_token = strdup(client_tok);

	browser_tok = json_object_get_string(
			json_object_object_get(arg_obj, "browserToken"));
	assert(browser_tok);
	wa->browser_token = strdup(browser_tok);

	secret = json_object_get_string(
			json_object_object_get(arg_obj, "secret"));
	assert(secret);
	wa->secret = strdup(secret);

	fprintf(stderr, "---------------- New session ---------------\n");
	fprintf(stderr, "server_token: %s\n", wa->server_token);
	fprintf(stderr, "client_token: %s\n", wa->client_token);
	fprintf(stderr, "browser_token: %s\n", wa->browser_token);
	fprintf(stderr, "secret: %s\n", wa->secret);
	fprintf(stderr, "--------------------------------------------\n");

	crypto_update_secret(wa->c, wa->secret);

	return 0;
}

int
wa_handle_json_array(wa_t *wa, struct json_object *array)
{
	struct json_object* action_obj;
	const char *action;

	action_obj = json_object_array_get_idx(array, 0);
	assert(action_obj);
	action = json_object_get_string(action_obj);
	assert(action);

	if(strcmp(action, "Conn") == 0)
		return wa_handle_conn(wa, array);

	return 0;
}

int
wa_handle_msg(wa_t *wa, msg_t *msg)
{
	/* Unsolicited message arrived */

	/* XXX A very unfortunate coincidence on binary data can lead to a
	 * beginning valid json sequence */

	struct json_tokener *tok = json_tokener_new();
	struct json_object *jo = json_tokener_parse_ex(tok, msg->cmd, msg->len);

	if(!jo)
	{
		return wa_handle_msg_bin(wa, msg);
	}

	if(tok->char_offset != msg->len)
	{
		fprintf(stderr, "Partial json detected. char_offset=%d, len=%ld\n",
				tok->char_offset, msg->len);

		return wa_handle_msg_bin(wa, msg);
	}

	fprintf(stderr, "JSON RECV: %s\n", ((char *) msg->cmd));

	if(json_object_is_type(jo, json_type_array))
	{
		return wa_handle_json_array(wa, jo);
	}

	fprintf(stderr, "Unknown json msg received\n");
	return 0;
}

msg_t *
wa_request(wa_t *wa, msg_t *msg)
{
	fprintf(stderr, "Sending msg:\n\ttag:%s\n\tcmd:%s\n",
		       msg->tag, (char *) msg->cmd);

	return dispatch_request(wa->d, msg);
}

void
wa_loop(wa_t *wa)
{
	msg_t *msg;

	while(wa->run)
	{
		msg = dispatch_wait_event(wa->d, 50);
		if(!msg) continue;

		wa_handle_msg(wa, msg);
	}

	dispatch_end(wa->d);
}

wa_t *
wa_init()
{
	wa_t *wa = calloc(1, sizeof(wa_t));
	wa->run = 1;

	wa->c = crypto_init();
	wa->d = dispatch_init();

	return wa;
}
