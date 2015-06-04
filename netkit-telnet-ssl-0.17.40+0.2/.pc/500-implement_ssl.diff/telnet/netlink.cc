#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netdb.h>
#include "netlink.h"
#include "proto.h"
#include "ring.h"

/* In Linux, this is an enum */
#if defined(__linux__) || defined(IPPROTO_IP)
#define HAS_IPPROTO_IP
#endif

netlink nlink;

class netchannel : public ringbuf::source {
  public:
    virtual int read(char *buf, int maxlen) {
	int net = nlink.getfd();
	int l = recv(net, buf, maxlen, 0);
	if (l<0 && errno == EWOULDBLOCK) l = 0;
	return l;
    }
};

class netchannel2 : public datasink {
  public:
    virtual int write(const char *buf, int len) {
	int r = nlink.send(buf, len, 0);
	if (r==-1 && (errno==ENOBUFS || errno==EWOULDBLOCK)) return 0;
	return r;
    }
    virtual int writeurg(const char *buf, int len) {
	    /*
	     * In 4.2 (and 4.3) systems, there is some question about
	     * what byte in a sendOOB operation is the "OOB" data.
	     * To make ourselves compatible, we only send ONE byte
	     * out of band, the one WE THINK should be OOB (though
	     * we really have more the TCP philosophy of urgent data
	     * rather than the Unix philosophy of OOB data).
	     */
	if (len==0) return 0;
	int r = nlink.send(buf, 1, MSG_OOB);
	if (r==-1 && (errno==ENOBUFS || errno==EWOULDBLOCK)) r = 0;
	if (r<=0) return r;
	int rr = nlink.send(buf+1, len-r, 0);
	if (rr==-1 && (errno==ENOBUFS || errno==EWOULDBLOCK)) rr = 0;
	if (rr<=0) return r;   /* less than ideal */
	return r+rr;
    }
};

static netchannel chan;
static netchannel2 chan2;
datasink *netsink = &chan2;
ringbuf::source *netsrc = &chan;


netlink::netlink() { net = -1; }
netlink::~netlink() { ::close(net); }


int netlink::setdebug(int debug) {
    if (net > 0 &&
	(setsockopt(net, SOL_SOCKET, SO_DEBUG, &debug, sizeof(debug))) < 0) {
	perror("setsockopt (SO_DEBUG)");
    }
    return 1;
}

void netlink::close(int doshutdown) {
    if (doshutdown) {
	shutdown(net, 2);
    }
    ::close(net);
    net = -1;
}

int netlink::bind(struct addrinfo *addr)
{
    int res;

    res = socket(addr->ai_family);
    if (res < 2) {
	if (res == 1)
	    perror("telnet: socket");
	return -1;
    }

    if (::bind(net, addr->ai_addr, addr->ai_addrlen) < 0) {
	perror("telnet: bind");
	return -1;
    }

    return 0;
}

int netlink::socket(int family)
{
    if (this->family != family)
	close(0);

    if (net < 0) {
	this->family = family;
	net = ::socket(family, SOCK_STREAM, 0);
	if (net < 0) {
	    if (errno == EAFNOSUPPORT)
		return 1;
	    perror("telnet: socket");
	    return 0;
	}
    }

    return 2;
}

int netlink::connect(int debug, struct addrinfo *addr, 
		     char *srcroute, int srlen, int tos) 
{
    int on=1;
    int res;

    res = socket(addr->ai_family);
    if (res < 2)
	return res;

#if defined(IP_OPTIONS) && defined(HAS_IPPROTO_IP)
    if (srcroute) {
	if (addr->ai_family != AF_INET)
	    fputs("Source route is only supported for IPv4\n", stderr);
	if (setsockopt(net, IPPROTO_IP, IP_OPTIONS, srcroute, srlen) < 0)
	    perror("setsockopt (IP_OPTIONS)");
    }
#endif

#if defined(HAS_IPPROTO_IP) && defined(IP_TOS)
#if defined(HAS_GETTOS)
    struct tosent *tp;
    if (tos < 0 && (tp = gettosbyname("telnet", "tcp")))
	tos = tp->t_tos;
#endif
    if (tos < 0) tos = 020;	/* Low Delay bit */
    if (tos && (setsockopt(net, IPPROTO_IP, IP_TOS, &tos, sizeof(int)) < 0)
	&& (errno != ENOPROTOOPT) && (errno != EOPNOTSUPP))
	perror("telnet: setsockopt (IP_TOS) (ignored)");
#endif	/* defined(IPPROTO_IP) && defined(IP_TOS) */

    if (debug && setsockopt(net, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) < 0) {
	perror("setsockopt (SO_DEBUG)");
    }
    
    if (::connect(net, addr->ai_addr, addr->ai_addrlen) < 0) {
	return 1;
    }
    return 2;
}


void netlink::oobinline() {
    int on=1;

    /* Systems without SO_OOBINLINE probably won't work */
    if (setsockopt(net, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on)) == -1) {
	perror("setsockopt");
    }
}


/*
 * Check to see if any out-of-band data exists on a socket (for
 * Telnet "synch" processing).
 */

int netlink::stilloob(void) {
    static struct timeval timeout = { 0, 0 };
    fd_set excepts;
    int value;

    do {
	FD_ZERO(&excepts);
	FD_SET(net, &excepts);
	value = select(net+1, NULL, NULL, &excepts, &timeout);
    } while ((value == -1) && (errno == EINTR));

    if (value < 0) {
	perror("select");
	quit();
	/* NOTREACHED */
    }
    if (FD_ISSET(net, &excepts)) {
	return 1;
    } else {
	return 0;
    }
}

int netlink::send(const char *s, int n, int f) {
    return ::send(net, s, n, f);
}

void netlink::nonblock(int onoff) {
    ioctl(net, FIONBIO, &onoff);
}

int netlink::getfd() {
    return net;
}
