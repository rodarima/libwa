#pragma once

#include "wa.h"
#include "buf.h"
#include "msg.h"

int
l1_recv_msg(wa_t *wa, msg_t *msg);

int
l1_send_keep_alive(wa_t *wa);

int
l1_send_buf(wa_t *wa, buf_t *in);
