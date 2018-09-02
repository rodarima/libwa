LDLIBS=-lcrypto -lwebsockets -ljson-c -lqrencode -pthread
CFLAGS=-g

all: wac

test: wa.o test.c

wac: wa.o ws.o qr.o
