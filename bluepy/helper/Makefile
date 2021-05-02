BUILD_UUID_JSON = ../build_uuid_json.py

CUR_DIR = $(realpath $(shell pwd))
TOP_DIR = $(realpath $(CUR_DIR)/../../)
BLUEPY_DIR = $(TOP_DIR)/bluepy/bluepy
BLUEZ_PATH = $(CUR_DIR)/bluez-5.47

BLUEZ_SRCS += lib/bluetooth.c
BLUEZ_SRCS += lib/hci.c
BLUEZ_SRCS += lib/sdp.c
BLUEZ_SRCS += lib/uuid.c
BLUEZ_SRCS += attrib/att.c
BLUEZ_SRCS += attrib/gatt.c
BLUEZ_SRCS += attrib/gattrib.c
BLUEZ_SRCS += attrib/utils.c
BLUEZ_SRCS += btio/btio.c
BLUEZ_SRCS += src/log.c
BLUEZ_SRCS += src/shared/mgmt.c
BLUEZ_SRCS += src/shared/crypto.c
BLUEZ_SRCS += src/shared/att.c
BLUEZ_SRCS += src/shared/queue.c
BLUEZ_SRCS += src/shared/util.c
BLUEZ_SRCS += src/shared/io-glib.c
BLUEZ_SRCS += src/shared/timeout-glib.c

BLUEZ_INCS += $(BLUEZ_PATH)
BLUEZ_INCS += $(BLUEZ_PATH)/attrib
BLUEZ_INCS += $(BLUEZ_PATH)/lib
BLUEZ_INCS += $(BLUEZ_PATH)/sys

IMPORT_SRCS = $(addprefix $(BLUEZ_PATH)/, $(BLUEZ_SRCS))
LOCAL_SRCS  = sources/bluepy-helper.c

CC ?= gcc
CFLAGS += -g -Wall -Wextra -Werror -Wno-unused-parameter

CPPFLAGS += -DHAVE_CONFIG_H
ifneq ($(DEBUGGING),)
CFLAGS += -DBLUEPY_DEBUG=1 -O0
else
CFLAGS += -Os
endif

CPPFLAGS += $(addprefix -I, $(BLUEZ_INCS))
CPPFLAGS += $(shell pkg-config glib-2.0 --cflags)

LDLIBS += $(shell pkg-config glib-2.0 --libs)

BLUEPY_HELPER = $(BLUEPY_DIR)/bluepy-helper

all: $(BLUEPY_HELPER)

$(BLUEPY_HELPER): $(LOCAL_SRCS) $(IMPORT_SRCS) Makefile
	$(CC) -L. $(CFLAGS) $(CPPFLAGS) -o $@ $(LOCAL_SRCS) $(IMPORT_SRCS) $(LDLIBS)

$(IMPORT_SRCS): bluez-src.tgz
	tar xzf $<
	touch $(IMPORT_SRCS)

.PHONY: bluez-tarfile

bluez-tarfile:
	(cd ..; tar czf bluepy/bluez-src.tgz $(BLUEZ_PATH))

BUILD_UUID_JSON = ../build_uuid_json.py

uuids.json: $(GET_SERVICES)
	$(BUILD_UUID_JSON) -w uuids.json

TAGS: *.c $(BLUEZ_PATH)/attrib/*.[ch] $(BLUEZ_PATH)/btio/*.[ch]
	etags $^

clean:
	rm -rf *.o bluepy-helper TAGS $(BLUEZ_PATH)
