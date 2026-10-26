CC ?= cc
CFLAGS ?= -O2 -fPIC -std=c11
CPPFLAGS += -I../../../src/plugin/shared_obj

.PHONY: all
all: so_plugin_test

so_plugin_test: so_plugin_test.c ../../../src/plugin/shared_obj/so_plugin.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared $(LDFLAGS) -o $@ $<
