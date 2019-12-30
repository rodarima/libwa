#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include "wa.h"
#include "dg.h"
#include "msg.h"

void
dump(FILE *f, const unsigned char *buf, const size_t len)
{
	size_t i,j,p;

	if(len == 0)
		return;

	f = stdout;

	for(i=0; i< 1 + (len-1)/16; i++)
	{
		for(j=0; j<16; j++)
		{
			p = i*16 + j;
			if(p < len)
				fprintf(f, "%02X ", (unsigned char) buf[p]);
			else
				fprintf(f, "   ");

			if(j == 7)
				fprintf(f, " ");
		}
		fprintf(f, "#  ");
		for(j=0; j<16; j++)
		{
			p = i*16 + j;
			if(p < len)
			{
				if(isprint(buf[p]))
					fprintf(f, "%c", buf[p]);
				else
					fprintf(f, ".");
			}
			else
			{
				break;
			}
		}
		fprintf(f, "\n");
	}
}

void
monitor_init(wa_t *wa, FILE *f)
{
	assert(f);
	wa->monitor_file = f;
}

void
monitor_msg(wa_t *wa, int layer, int is_out, msg_t *msg)
{
	FILE *f;
	char dirc[] = {'>', '<'};

	assert(is_out == 0 || is_out == 1);

	f = wa->monitor_file;

	fprintf(f, "%c l%d m\n", dirc[is_out], layer);
	fprintf(f, "# tag = %s\n", msg->tag);
	dump(f, (unsigned char *) msg->tag, strlen(msg->tag));
	fprintf(f, ",\n");
	fprintf(f, "# cmd len=%ld\n", msg->len);
	dump(f, msg->cmd, msg->len);
	fprintf(f, "---\n");
}

void
monitor_buf(wa_t *wa, int layer, int is_out, unsigned char *buf, size_t len)
{
	FILE *f;
	char dirc[] = {'>', '<'};

	assert(is_out == 0 || is_out == 1);

	f = wa->monitor_file;

	fprintf(f, "%c l%d b\n", dirc[is_out], layer);
	fprintf(f, "# buf len=%ld\n", len);
	dump(f, buf, len);
	fprintf(f, "---\n");
}

void
monitor_dg(wa_t *wa, dg_t *dg)
{
	FILE *f;
	const char *meta;
	f = wa->monitor_file;

	fprintf(f, ".DATAGRAM L%d TO L%d\n", dg->src, dg->dst);
	if(dg->meta)
	{
		fprintf(f, ".METADATA\n");
		meta = json_object_to_json_string(dg->meta);
		dump(f, (const unsigned char *) meta, strlen(meta));
	}
	if(dg->data)
	{
		fprintf(f, ".DATA\n");
		dump(f, dg->data->ptr, dg->data->len);
	}

	fprintf(f, ".END\n");

	/* Add an empty line to help reading the datagrams */
	fprintf(f, "\n");


}
