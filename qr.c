#include <stdio.h>
#include <qrencode.h>

#define BK_WH   "\x1b[40m\x1b[37m"
#define DF_DF  "\x1b[49m\x1b[39m"
#define RV(x)  ( "\x1b[7m" x "\x1b[0m" )
#define BLK   "  "

#define BORDER 1

void qr_encode(char *s)
{
	QRcode* qr;
	int i, j, jj, total_size, qr_size;
	unsigned char c;
	const char *dot[2] = {RV(BLK), BLK};

	qr = QRcode_encodeString(s, 0, QR_ECLEVEL_L, QR_MODE_8, 1);

	qr_size = qr->width;
	total_size = qr_size + BORDER * 2;

	printf(BK_WH);
	for(i=0; i < BORDER; i++)
	{
		for(j=0; j < total_size; j++)
		{
			printf(dot[0]);
		}
		printf("\n");
	}

	for(i=0; i < qr->width; i++)
	{
		for(j=0; j < total_size; j++)
		{
			jj = j - BORDER;
			if ((jj < 0) || (jj>=qr_size))
				c = 0;
			else
				c = qr->data[i*qr->width + jj] & 0x01;

			printf(dot[c]);
		}
		printf("\n");
	}
	for(i=0; i < BORDER; i++)
	{
		for(j=0; j < total_size; j++)
		{
			printf(dot[0]);
		}
		printf("\n");
	}
	printf(DF_DF);

	QRcode_free(qr);
}

/*
int main()
{
	qr_encode("laraaailoo");
}
*/
