module := client
src := $(wildcard $(module)/*.c)
obj := $(subst .c,.o,$(src))

LDLIBS := -lcrypto -lwebsockets -ljson-c -lqrencode -lprotobuf-c -pthread
LDFLAGS = -rpath "\$$ORIGIN"

wac: $(obj) libwa.so
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LDLIBS) $?

BIN += wac
