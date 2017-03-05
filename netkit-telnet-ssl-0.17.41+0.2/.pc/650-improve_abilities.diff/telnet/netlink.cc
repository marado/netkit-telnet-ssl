#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netdb.h>
#include "netlink.h"
#include "proto.h"
#include "ring.h"
#include <libtelnet/sslapp.h>
#include <libtelnet/misc-proto.h>

/* In Linux, this is an enum */
#if defined(__linux__) || defined(IPPROTO_IP)
#define HAS_IPPROTO_IP
#endif

/* code from Peter 'Luna' Runestig <peter@runestig.com> */
static int select_read(int rfd)
/* timeout = 20 seconds */
{
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(rfd, &rfds);
    tv.tv_sec = 20;
    tv.tv_usec = 0;
    return select(rfd + 1, &rfds, NULL, NULL, &tv);
}

netlink nlink;

class netchannel : public ringbuf::source {
  public:
    virtual int read(char *buf, int maxlen) {
	int net = nlink.getfd();
	int l;
#ifdef USE_SSL
	if (ssl_active_flag) {
	    do {
		l = SSL_read(ssl_con, buf, maxlen);
		/*
		 * SSL_ERROR_WANT_READ may occur if an SSL/TLS rehandshake occurs.
		 * This means that data was available at the socket, but all was
		 * consumed by SSL itself, so we select (w/20s timeout)  and retry.
		 */
	    } while (l<0 &&
		     (SSL_ERROR_WANT_READ == SSL_get_error(ssl_con, l)) &&
		     (select_read(net) > 0));
        } else
#endif /* USE_SSL */
        {
  	    l = recv(net, buf, maxlen, 0);
	    if (l<0 && errno == EWOULDBLOCK) l = 0;
        }
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
netlink::~netlink() { if (net >= 0) ::close(net); }


int netlink::setdebug(int debug) {
    if (net >= 0 &&
	(setsockopt(net, SOL_SOCKET, SO_DEBUG, &debug, sizeof(debug))) < 0) {
	perror("setsockopt (SO_DEBUG)");
    }
    return 1;
}

void netlink::close(int doshutdown) {
    if (doshutdown) {
	shutdown(net, 2);
    }
#ifdef USE_SSL
    if (ssl_active_flag) {
	if (ssl_debug_flag)
	  BIO_printf(bio_err,"NetClose: calling SSL_shutdown\n");
	SSL_shutdown(ssl_con);
	SSL_free(ssl_con);
	ssl_con=NULL;
	ssl_active_flag=0;
    }
#endif /* USE_SSL */
    if (net >= 0)
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
    extern char *hostname;
    
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
#ifdef USE_SSL
	if (!do_ssleay_init(0)) {
	  if (bio_err==NULL) {
	    fflush(stdout);
	    fflush(stderr);
	    fprintf(stderr,"do_ssleay_init() failed\n");
	    ERR_print_errors_fp(stderr);
	  } else {
	    BIO_printf(bio_err,"do_ssleay_init() failed\n");
	    ERR_print_errors(bio_err);
	  }
	  exit(1);
	}
	
	/* bind in the network descriptor */
    	SSL_set_fd(ssl_con,net);

#if defined(AUTHENTICATE)
	/* moved from telnet() so client_verify_callback knows RemoteHostName -ianb */
	{
	  static char local_host[256] = { 0 };
	  int len = sizeof(local_host);

	  if (!local_host[0]) {
	    gethostname(local_host, len);        /* WAS &len!!! */
	    local_host[sizeof(local_host)-1] = 0;
	  }
	  auth_encrypt_init(local_host, hostname, "TELNET", 0);
	}
#endif

	/* if we are doing raw SSL then start it now ... */
	if (ssl_only_flag) {
	    int rc = SSL_connect(ssl_con);

	    if (rc <= 0) {
		/* static char errbuf[1024]; */
		char *res, *p;
		int err = SSL_get_error(ssl_con, rc);

		if (!errno)
		  errno = EIO;
		res = ERR_error_string(ERR_peek_last_error(), NULL);
		p = strrchr(res, ':');
		fprintf(stderr,"SSL: %s\n", p ? &p[1] : res);
		if (err == SSL_ERROR_SSL)
		  fprintf(stderr, "%s: %s\n", hostname,
			  "Error during SSL negotiation.");
		else {
		  ERR_print_errors_fp(stderr);
		  perror("SSL_Connect");
		}
		fflush(stderr);

		exit(1);
	    } else {
		display_connect_details(ssl_con,ssl_debug_flag);
		ssl_active_flag=1;
	    }
	}

#endif /* USE_SSL */
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
#ifdef USE_SSL
    if (ssl_active_flag)
        return SSL_write(ssl_con, s, n); /* normal write */
    else
#endif /* USE_SSL */
    return ::send(net, s, n, f);
}

void netlink::nonblock(int onoff) {
#ifndef USE_SSL
    ioctl(net, FIONBIO, &onoff);
#endif /* !USE_SSL */
}

int netlink::getfd() {
    return net;
}
