#pragma once

#include "wa.h"
#include "pmsg.pb-c.h"

int
l4_recv_msg(wa_t *wa, unsigned char *buf, size_t len, int last);

int
l4_send_priv_msg(wa_t *wa, char *to_jid, char *text);
