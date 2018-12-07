CC := clang
MODULES := libwa client

CFLAGS=-g -Wall -Werror -fPIC

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
	$(CC) -MM -MG $(CFLAGS) $*.c \
	| sed -e 's@^\(.*\)\.o:@\1.d \1.o:@' > $@

all: $(BIN)

install: $(BIN)
	cp libwa.so $(INSTALL_DIR)/lib/
	mkdir -p $(INSTALL_DIR)/include/libwa/
	cp *.h $(INSTALL_DIR)/include/libwa/

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) $(BIN)

