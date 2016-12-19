all: telnet

include ../MCONFIG
include ../MRULES

# ignore imported LIBS value, drags in too much
LIBS=

#CXXFLAGS:=$(patsubst -O2, -g, $(CXXFLAGS))

# -DAUTHENTICATE
CXXFLAGS += -DUSE_TERMIO -DKLUDGELINEMODE -DAUTHENTICATE -DUSE_SSL \
	-I/usr/include/openssl -I../
LIBTELNET = ../libtelnet/libtelnet.a
LIBS += $(LIBTERMCAP) $(LIBTELNET) -lssl -lcrypto

SRCS = commands.cc main.cc network.cc ring.cc sys_bsd.cc telnet.cc \
	terminal.cc tn3270.cc utilities.cc genget.cc environ.cc netlink.cc \
	glue.cc glue2.cc

OBJS = $(patsubst %.cc, %.o, $(SRCS))
telnet: $(OBJS) $(LIBTELNET)
	$(CXX) -static-libgcc $(LDFLAGS) $^ $(LIBS) -o $@

include depend.mk
depend:
	$(CXX) $(CXXFLAGS) -MM $(SRCS) >depend.mk

install: telnet
	install -m$(BINMODE) telnet $(INSTALLROOT)$(BINDIR)/telnet-ssl
	install -m$(MANMODE) telnet.1 $(INSTALLROOT)$(MANDIR)/man1/telnet-ssl.1

clean:
	rm -f *.o telnet

