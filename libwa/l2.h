#pragma once

#include "wa.h"
#include "msg.h"

int
l2_recv_msg(wa_t *wa, msg_t *msg_l2);

int
l2_send_buf(wa_t *wa, buf_t *in, char *tag, int metric, int flags);

int
l2_send_plain(wa_t *wa, buf_t *in, char *tag, int metric, int flags);
