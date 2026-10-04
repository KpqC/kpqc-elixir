MIX_APP_PATH ?= _build/dev/lib/kpqc
ERTS_INCLUDE_DIR ?= /usr/lib/erlang/erts/include

CC ?= cc
CFLAGS ?= -O3
CFLAGS += -std=c11 -fPIC -fvisibility=hidden
CPPFLAGS += -I$(ERTS_INCLUDE_DIR) $(KPQC_CPPFLAGS)

SOURCES := c_src/kpqc_nif.c $(wildcard c_src/core_*.c)
OBJECTS := $(patsubst c_src/%.c,$(MIX_APP_PATH)/obj/%.o,$(SOURCES))
DEPS := $(OBJECTS:.o=.d)
NIF := $(MIX_APP_PATH)/priv/kpqc_nif.so

HAETAE_OBJECTS := $(addprefix $(MIX_APP_PATH)/obj/,core_haetae2.o \
	core_haetae3.o core_haetae5.o)
SMAUGT_OBJECTS := $(addprefix $(MIX_APP_PATH)/obj/,core_smaugt128.o \
	core_smaugt192.o core_smaugt256.o core_timer.o)

$(HAETAE_OBJECTS): CPPFLAGS += -Ic_src/third_party/HAETAE/include
$(SMAUGT_OBJECTS): CPPFLAGS += -Ic_src/third_party/SMAUG-T/include
$(MIX_APP_PATH)/obj/core_ntruplus768.o: CPPFLAGS += -Ic_src/third_party/NTRUplus/NTRU+768
$(MIX_APP_PATH)/obj/core_ntruplus864.o: CPPFLAGS += -Ic_src/third_party/NTRUplus/NTRU+864
$(MIX_APP_PATH)/obj/core_ntruplus1152.o: CPPFLAGS += -Ic_src/third_party/NTRUplus/NTRU+1152

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LDFLAGS_NIF := -bundle -undefined dynamic_lookup
else ifeq ($(UNAME_S),Linux)
  LDFLAGS_NIF := -shared
else
  $(error kpqc currently supports macOS and Linux)
endif

.PHONY: all clean

all: $(NIF)

$(NIF): $(OBJECTS)
	@mkdir -p "$(@D)"
	$(CC) $(LDFLAGS_NIF) -o "$@" $(OBJECTS) -lm

$(MIX_APP_PATH)/obj/%.o: c_src/%.c
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c "$<" -o "$@"

clean:
	$(RM) $(OBJECTS) $(DEPS) "$(NIF)"

-include $(DEPS)
