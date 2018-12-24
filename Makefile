#CC := gcc
CC := clang
MODULES := libwa client test

CFLAGS=-g -Wall -Werror -fPIC -I/usr/include

# Search dynamic libraries in the current path
#LDFLAGS = -Wl,-rpath="\$$ORIGIN"
LDFLAGS = -Wl,-rpath="."

INSTALL_DIR=/usr

all:

# look for include files in each of the modules
CFLAGS += $(patsubst %,-I%,$(MODULES))

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
	gcc -MM -MG $(CFLAGS) $*.c \
	| sed -e 's@^\(.*\)\.o:@\1.d \1.o:@' > $@

all: $(BIN)

install: $(BIN)
	cp libwa.so $(INSTALL_DIR)/lib/
	mkdir -p $(INSTALL_DIR)/include/libwa/
	cp libwa/*.h $(INSTALL_DIR)/include/libwa/

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) $(BIN)

