#include "wire.h"

#include "wa.h"
#include "dg.h"

#include "l1.h"
#include "l2.h"
#include "l3.h"
#include "l4.h"

#include "monitor.h"

#include "log.h"

/* Blocking send */
static int
wire_send(wa_t *wa, dg_t *dg)
{
	int ret;

	switch(dg->dst)
	{
//		case L0: ret = l0_send(wa, dg); break;
		case L1: ret = l1_send(wa, dg); break;
		case L2: ret = l2_send(wa, dg); break;
		case L3: ret = l3_send(wa, dg); break;
//		case L4: ret = l4_send(wa, dg); break;
		default:
			 LOG_ERR("Unknown datagram dst=%d\n", dg->dst);
			 abort();
	}

	return ret;
}

/* Blocking recv */
static int
wire_recv(wa_t *wa, dg_t *dg)
{
	int ret;

	switch(dg->dst)
	{
//		case L0: ret = l0_recv(wa, dg); break;
		case L1: ret = l1_recv(wa, dg); break;
		case L2: ret = l2_recv(wa, dg); break;
		case L3: ret = l3_recv(wa, dg); break;
		case L4: ret = l4_recv(wa, dg); break;
		default:
			 LOG_ERR("Unknown datagram dst=%d\n", dg->dst);
			 abort();
	}

	return ret;
}

int
wire_handle(wa_t *wa, dg_t *dg)
{
	monitor_dg(wa, dg);

	if(dg->src < dg->dst)
	{
		/* Going up */
		return wire_recv(wa, dg);
	}

	if(dg->src > dg->dst)
	{
		/* Going down */
		return wire_send(wa, dg);
	}

	LOG_ERR("Same source and destination in datagram");
	return 1;
}
