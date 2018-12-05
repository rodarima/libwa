#include "l1.h"
#include "l2.h"

#define DEBUG LOG_LEVEL_INFO

#include "log.h"
#include "wa.h"
#include <json-c/json.h>
#include <assert.h>


static int
l1_recv_msg_bin(wa_t *wa, msg_t *msg_l1)
{
	LOG_INFO("RECV BIN: tag:%s len:%lu\n",
			msg_l1->tag, msg_l1->len);

	return l2_recv_msg(wa, msg_l1);
}

static int
l1_recv_conn(wa_t *wa, struct json_object *array)
{
	if(wa->state != WA_STATE_LOGGING)
	{
		LOG_INFO("Recv conn msg but not wanted\n");
		return 0;
	}

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

	LOG_INFO("---------------- New session ---------------\n");
	LOG_INFO("server_token: %s\n", wa->server_token);
	LOG_INFO("client_token: %s\n", wa->client_token);
	LOG_INFO("browser_token: %s\n", wa->browser_token);
	LOG_INFO("secret: %s\n", wa->secret);
	LOG_INFO("--------------------------------------------\n");

	crypto_update_secret(wa->c, wa->secret);

	wa->state = WA_STATE_LOGGED_IN;

	return 0;
}

static int
l1_recv_json_array(wa_t *wa, struct json_object *array)
{
	struct json_object* action_obj;
	const char *action;

	action_obj = json_object_array_get_idx(array, 0);
	assert(action_obj);
	action = json_object_get_string(action_obj);
	assert(action);

	if(strcmp(action, "Conn") == 0)
	{
		return l1_recv_conn(wa, array);
	}

	return 0;
}

int
l1_recv_msg(wa_t *wa, msg_t *msg)
{
	/* Unsolicited message arrived */

	/* A very unfortunate coincidence on binary data can lead to a
	 * beginning valid json sequence */

	struct json_tokener *tok = json_tokener_new();
	struct json_object *jo = json_tokener_parse_ex(tok, msg->cmd, msg->len);

	if(!jo)
	{
		return l1_recv_msg_bin(wa, msg);
	}

	if(tok->char_offset != msg->len)
	{
		LOG_INFO("Partial json detected. char_offset=%d, len=%ld\n",
				tok->char_offset, msg->len);

		return l1_recv_msg_bin(wa, msg);
	}

	LOG_WARN("JSON RECV: %s\n", ((char *) msg->cmd));

	if(json_object_is_type(jo, json_type_array))
	{
		return l1_recv_json_array(wa, jo);
	}

	LOG_ERR("Unknown json msg received\n");
	return 0;
}

int
l1_send_keep_alive(wa_t *wa)
{
	/* We need to send the byte string "?,," without null terminator to the
	 * server, and with a random interval between 20000 and 90000 ms.
	 */

	struct timespec ts;
	msg_t *msg;
	int r, rmin = 20, rmax = 90;

	if(wa->state != WA_STATE_LOGGED_IN)
		return 0;

	clock_gettime(CLOCK_REALTIME, &ts);

	if(wa->keep_alive_next > ts.tv_sec)
		return 0;

	LOG_INFO("Sending keep alive\n");

	msg = malloc(sizeof(msg_t));
	assert(msg);

	msg->tag = "?";
	msg->cmd = ",";
	msg->len = 1;

	if(dispatch_send_msg(wa->d, msg))
		return -1;

	free(msg);

	r = rmin + (rand() % (rmax - rmin));
	wa->keep_alive_next = ts.tv_sec + r;

	return 0;
}
