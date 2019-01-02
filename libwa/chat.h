#pragma once

#include <uthash.h>

#include "wa.h"

chat_t *
chat_init();

int
chat_recv_priv_msg(wa_t *wa, priv_msg_t *pm);

int
chat_update(wa_t *wa, char *jid, int count);

int
chat_flush_conv(wa_t *wa, conv_t *conv);

int
chat_flush_jid(wa_t *wa, char *jid);

int
chat_flush(wa_t *wa);
