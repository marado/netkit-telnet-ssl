include ../MCONFIG
include ../MRULES

LIB=	telnet

OBJS=	auth.o misc.o ssl.o sslapp.o

CFLAGS += -DAUTHENTICATE -DUSE_SSL -I/usr/include/openssl -I.

lib${LIB}.a: ${OBJS}
	echo building standard ${LIB} library 
	rm -f lib${LIB}.a 
	ar cq lib${LIB}.a ${OBJS}; \
	if [ -f /usr/bin/ranlib ]; then \
		ranlib lib${LIB}.a; \
	fi;

clean:
	rm -f *.o lib${LIB}.a
