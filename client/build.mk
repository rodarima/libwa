module := client
src := $(wildcard $(module)/*.c)
obj := $(subst .c,.o,$(src))

LDLIBS := -lcrypto -lwebsockets -ljson-c -lqrencode -lprotobuf-c -pthread

wac: $(obj) libwa.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LDLIBS) $^

BIN += wac
SRC += $(src)
