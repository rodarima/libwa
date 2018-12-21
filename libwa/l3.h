#pragma once

#include "wa.h"
#include "msg.h"

int
l3_recv_msg(wa_t *wa, msg_t *msg_l2);

int
l3_send_relay(wa_t *wa, buf_t *buf);
