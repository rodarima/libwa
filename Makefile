LDLIBS=-lcrypto -lwebsockets -ljson-c -lqrencode -pthread
CFLAGS=-g -Wall -Werror

all: wac

test: wa.o test.c

wac: dispatcher.c wa.o ws.o qr.o crypto.o

clean:
	rm -rf *.o wac
