module := test
src := $(wildcard $(module)/*.c)
obj := $(subst .c,.o,$(src))

$(module)/test: $(obj) libwa.so

SRC += $(src)
BIN += $(module)/test
