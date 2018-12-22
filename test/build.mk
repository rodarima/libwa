module := test
src := $(wildcard $(module)/*.c)
obj := $(subst .c,.o,$(src))

$(module)/test: $(module)/test.o libwa.so
$(module)/decrypt: $(module)/decrypt.o libwa.so

SRC += $(src)
BIN += $(module)/test $(module)/decrypt
