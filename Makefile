LDLIBS=-lcrypto -lwebsockets -ljson-c -lqrencode -lprotobuf-c -pthread
CFLAGS=-g -Wall -Werror

all: wac

test: wa.o test.c

wac: dispatcher.c wa.o ws.o qr.o crypto.o bnode.o pmsg.o pmsg.pb-c.o session.o

bnode: crypto.o pmsg.o pmsg.pb-c.o

pmsg.pb-c.c: pmsg.proto
	protoc-c --c_out=. pmsg.proto

clean:
	rm -rf *.o pmsg.pb-c.* wac
