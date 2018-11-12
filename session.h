#pragma once

#include <uthash.h>

#include "wa.h"
#include "bnode.h"



int
session_recv_priv_msg(wa_t *wa, priv_msg_t *pm);

user_t *
session_find_user(wa_t *wa, const char *jid);

int
session_update_user(wa_t *w, user_t *u);

int
session_restore(wa_t *wa);

int
session_new(wa_t *wa);
