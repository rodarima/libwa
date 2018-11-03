#pragma once

#include "session.h"
#include "pmsg.pb-c.h"

int
pmsg_parse_message(session_t *s, char *buf, size_t len);
