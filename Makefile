LDLIBS=-lcrypto -lwebsockets -ljson-c -lqrencode -lprotobuf-c -pthread
CFLAGS=-g -Wall -Werror

all: wac

test: wa.o test.c

wac: dispatcher.c wa.o ws.o qr.o crypto.o bnode.o

bnode: crypto.o

def.pb-c.c: def.proto
	protoc --c_out=. def.proto

clean:
	rm -rf *.o def.pb-c.* wac
