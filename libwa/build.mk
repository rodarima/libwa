module := libwa
src := $(wildcard $(module)/*.c)
obj := $(subst .c,.o,$(src))

src += $(module)/pmsg.pb-c.c

libs := -lcrypto -lwebsockets -ljson-c -lqrencode -lprotobuf-c -pthread

$(module)/pmsg.pb-c.c: $(module)/pmsg.proto
	protoc-c --c_out=. $?

libwa.so: $(obj)
	$(CC) $(CFLAGS) -shared $^ -o $@ $(libs)

libwa.a: $(obj)
	ar rcs $@ $^

SRC += $(src)
BIN += libwa.so libwa.a
