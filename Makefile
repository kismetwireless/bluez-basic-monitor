
MONITOR_OBJS = \
	gdbus/client.c.o \
	gdbus/mainloop.c.o \
	gdbus/object.c.o \
	gdbus/polkit.c.o \
	gdbus/watch.c.o \
	linux_bt_rfkill.c.o \
	bluez-monitor.c.o
MONITOR_BIN = bluez-monitor

MGMT_OBJS = \
	mgmtlib/bluetooth.c.o \
	mgmtlib/hci.c.o \
	mgmtlib/sdp.c.o \
	mgmtlib/uuid.c.o \
	linux_bt_rfkill.c.o \
	simple_ringbuf_c.c.o \
	bluez-mgmtsock.c.o
MGMT_BIN = bluez-monitor-mgmtsock

CC = gcc
LD = gcc
CFLAGS = -I. `pkg-config glib-2.0 --cflags` `pkg-config dbus-glib-1 --cflags`
LDFLAGS = 
LIBS = `pkg-config glib-2.0 --libs` `pkg-config dbus-glib-1 --libs` -ldl

all: $(MONITOR_BIN) $(MGMT_BIN)

$(MONITOR_BIN):	$(MONITOR_OBJS) $(patsubst %c.o,%c.d,$(MONITOR_OBJS))
		$(LD) $(LDFLAGS) -o $(MONITOR_BIN) $(MONITOR_OBJS) $(LIBS) 

$(MGMT_BIN):	$(MGMT_OBJS) $(patsubst %c.o,%c.d,$(MGMT_OBJS))
		$(LD) $(LDFLAGS) -o $(MGMT_BIN) $(MGMT_OBJS) $(LIBS) 

clean:
	@rm *.o
	@rm *.d
	@rm gdbus/*.o
	@rm gdbus/*.d

%.c.o:	%.c
%.c.o : %.c %.c.d
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $*.c -o $@

%.c.d:	%.c
	$(CC) -MM $(CFLAGS) $(CPPFLAGS) $*.c | sed -e "s/\.o/\.c.o/" > $*.c.d

.PRECIOUS: %.c.d

include $(wildcard $(patsubst %c.o,%c.d,$(MONITOR_OBJS)))
include $(wildcard $(patsubst %c.o,%c.d,$(MGMT_OBJS)))

