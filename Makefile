LDLIBS=-lcrypto -lwebsockets -ljson-c -lqrencode -lprotobuf-c -pthread
CFLAGS=-g -Wall -Werror -fPIC

LIB_CFLAGS=$(CFLAGS) -shared
INSTALL_DIR=/usr

all: libwa.so wac

test: wa.o test.c

wac: dispatcher.c wa.o ws.o qr.o crypto.o pmsg.pb-c.o bnode.o pmsg.o session.o

libwa.so: dispatcher.o wa.o ws.o qr.o crypto.o pmsg.pb-c.o bnode.o pmsg.o session.o
	$(CC) $(LIB_CFLAGS) $^ -o $@ $(LDLIBS)

bnode: crypto.o pmsg.o pmsg.pb-c.o

pmsg.pb-c.o: pmsg.pb-c.c

pmsg.pb-c.c: pmsg.proto
	protoc-c --c_out=. pmsg.proto

install: libwa.so
	cp libwa.so $(INSTALL_DIR)/lib/
	mkdir -p $(INSTALL_DIR)/include/libwa/
	cp *.h $(INSTALL_DIR)/include/libwa/

clean:
	rm -rf *.o pmsg.pb-c.* wac
