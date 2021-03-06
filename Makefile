#CC := gcc
CC := clang
MODULES := libwa client test

CFLAGS=-g -Wall -Wextra -fPIC -I/usr/include
#CFLAGS=-g -Wall -Werror -fsanitize=address -O1 -fno-omit-frame-pointer -fPIC -I/usr/include
CFLAGS+=-Werror
CFLAGS+=-Wno-unused-parameter # Avoid a lot of false positives by now

# Search dynamic libraries in the current path
#LDFLAGS = -Wl,-rpath="\$$ORIGIN"
LDFLAGS = -Wl,-rpath="."
#LDFLAGS = -Wl,-rpath="." -fsanitize=address

INSTALL_DIR=/usr

all:

# look for include files in each of the modules
CFLAGS += $(patsubst %,-I%,$(MODULES)) -I.

LDLIBS :=
BIN :=
SRC :=

# include the description for each module
include $(patsubst %,%/build.mk,$(MODULES))

# determine the object files
OBJ := \
$(patsubst %.c,%.o, $(filter %.c,$(SRC))) \
$(patsubst %.y,%.o, $(filter %.y,$(SRC)))

# include the C include dependencies
include $(OBJ:.o=.d)

# calculate C include dependencies
%.d: %.c
	gcc -MM -MG $*.c \
	| sed -e 's@^\(.*\)\.o:@\1.d \1.o:@' > $@

all: $(BIN)

install: $(BIN)
	cp -f libwa.so $(INSTALL_DIR)/lib/
	mkdir -p $(INSTALL_DIR)/include/libwa/
	cp -f libwa/*.h $(INSTALL_DIR)/include/libwa/

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) $(BIN)

