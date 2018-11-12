CC=clang
LDLIBS=-lcrypto -lwebsockets -ljson-c -lqrencode -lprotobuf-c -pthread
CFLAGS=-g -Wall -Werror -fPIC

LIB_CFLAGS=$(CFLAGS) -shared
INSTALL_DIR=/usr

FILES = $(wildcard *.c)
OBJS = $(subst .c,.o,$(FILES))

all: wac libwa.so

test: wa.o test.c

wac: $(OBJS)

libwa.so: $(OBJS)
	$(CC) $(LIB_CFLAGS) $^ -o $@ $(LDLIBS)

bnode: crypto.o l4.o pmsg.pb-c.o

pmsg.pb-c.o: pmsg.pb-c.c

pmsg.pb-c.c: pmsg.proto
	protoc-c --c_out=. pmsg.proto

install: libwa.so
	cp libwa.so $(INSTALL_DIR)/lib/
	mkdir -p $(INSTALL_DIR)/include/libwa/
	cp *.h $(INSTALL_DIR)/include/libwa/

clean:
	rm -rf *.o pmsg.pb-c.* wac
