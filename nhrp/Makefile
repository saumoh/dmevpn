progs-y			+= opennhrp
opennhrp-objs		+= libev.o opennhrp.o nhrp_address.o nhrp_packet.o \
			   nhrp_peer.o nhrp_server.o nhrp_interface.o admin.o \
			   sysdep_netlink.o sysdep_pfpacket.o \
			   sysdep_syslog.o

CFLAGS_libev.o		+= -Wno-unused -Wno-comment -Wno-parentheses
CFLAGS_opennhrp.o	+= -DOPENNHRP_VERSION=\"$(FULL_VERSION)\" \
			   -DOPENNHRP_ADMIN_SOCKET=\"$(STATEDIR)/opennhrp.socket\"
LIBS_opennhrp		+= -lm
ifeq ($(shell pkg-config --exists libcares && echo "yes"),yes)
CFLAGS			+=$(shell pkg-config --cflags libcares)
LIBS_opennhrp  		+=$(shell pkg-config --libs libcares)
else
LIBS_opennhrp  		+= -lcares
endif

progs-y			+= opennhrpctl
opennhrpctl-objs	+= opennhrpctl.o
CFLAGS_opennhrpctl.o	+= $(CFLAGS_opennhrp.o)

CFLAGS_EXTRA		+= -I$(srctree)/include -Wno-strict-aliasing

install:
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(addprefix $(obj)/,$(progs-y)) $(DESTDIR)$(SBINDIR)

