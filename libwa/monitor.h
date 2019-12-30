#include "msg.h"

void
monitor_init(wa_t *wa, FILE *f);

void
monitor_msg(wa_t *wa, int layer, int is_out, msg_t *msg);

void
monitor_buf(wa_t *wa, int layer, int is_out, unsigned char *buf, size_t len);

void
monitor_dg(wa_t *wa, dg_t *dg);
