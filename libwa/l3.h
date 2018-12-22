#pragma once

#include "wa.h"
#include "msg.h"
#include "bnode.h"

int
l3_recv_msg(wa_t *wa, msg_t *msg_l2);

int
l3_send_relay(wa_t *wa, bnode_t *b, char *tag);

int
l3_send_relay_msg(wa_t *wa, buf_t *buf, char *tag);
