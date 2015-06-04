/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

char copyright[] =
  "@(#) Copyright (c) 1989 Regents of the University of California.\n"
  "All rights reserved.\n";

/*
 * From: @(#)telnetd.c	5.48 (Berkeley) 3/1/91
 */
char telnetd_rcsid[] = 
  "$Id: telnetd.c,v 1.6 2004/12/21 18:14:29 ianb Exp $";

#include "../version.h"

#include <sys/socket.h>
#include <netdb.h>
#include <termcap.h>
#include <netinet/in.h>
/* #include <netinet/ip.h> */ /* Don't think this is used at all here */
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include "telnetd.h"
#include "pathnames.h"
#include "setproctitle.h"

#if	defined(AUTHENTICATE)
#include <libtelnet/auth.h>
#include <libtelnet/auth-proto.h>
#include <libtelnet/misc-proto.h>
int	auth_level = 0;
#endif
#if	defined(SecurID)
int	require_SecurID = 0;
#endif

/* In Linux, this is an enum */
#if defined(__linux__) || defined(IPPROTO_IP)
#define HAS_IPPROTO_IP
#endif

static void doit(struct sockaddr *who, socklen_t who_len);
static int terminaltypeok(const char *s);

#ifdef USE_SSL 
static char cert_filepath[1024];
#endif /* USE_SSL */

/*
 * I/O data buffers,
 * pointers, and counters.
 */
char	ptyibuf[BUFSIZ], *ptyip = ptyibuf;
char	ptyibuf2[BUFSIZ];

int	hostinfo = 1;			/* do we print login banner? */

int debug = 0;
int keepalive = 1;
int numeric_hosts = 0;
#ifdef LOGIN_WRAPPER
char *loginprg = LOGIN_WRAPPER;
#else
char *loginprg = _PATH_LOGIN;
#endif

extern void usage(void);

static void
wait_for_connection(const char *service)
{
	struct addrinfo hints;
	struct addrinfo *res, *addr;
	struct pollfd *fds, *fdp;
	int nfds;
	int i;
	int error;
	int on = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(NULL, service, &hints, &res);
	if (error) {
		char *p;
		error = asprintf(&p, "getaddrinfo: %s\n", gai_strerror(error));
		fatal(2, error >= 0 ? p : "");
	}

	for (addr = res, nfds = 0; addr; addr = addr->ai_next, nfds++)
		;
	fds = malloc(sizeof(struct pollfd) * nfds);
	for (addr = res, fdp = fds; addr; addr = addr->ai_next, fdp++) {
		int s;

		if (addr->ai_family == AF_LOCAL) {
nextaddr:
			fdp--;
			nfds--;
			continue;
		}

		s = socket(addr->ai_family, SOCK_STREAM, 0);
		if (s < 0) {
			if (errno == EAFNOSUPPORT || errno == EINVAL) {
				goto nextaddr;
			}
			fatalperror(2, "socket");
		}
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
			fatalperror(2, "setsockopt");
		}
		if (bind(s, addr->ai_addr, addr->ai_addrlen)) {
#ifdef linux
			if (fdp != fds && errno == EADDRINUSE) {
				close(s);
				goto nextaddr;
			}
#endif
			fatalperror(2, "bind");
		}
		if (listen(s, 1)) {
			fatalperror(2, "listen");
		}
		if (fcntl(s, F_SETFL, O_NONBLOCK)) {
			fatalperror(2, "fcntl");
		}

		fdp->fd = s;
		fdp->events = POLLIN;
	}

	freeaddrinfo(res);

	while (1) {
		if (poll(fds, nfds, -1) < 0) {
			if (errno == EINTR) {
				continue;
			}
			fatalperror(2, "poll");
		}

		for (i = 0, fdp = fds; i < nfds; i++, fdp++) {
			int fd;

			if (!(fdp->revents & POLLIN)) {
				continue;
			}

			fd = accept(fdp->fd, 0, 0);
			if (fd >= 0) {
				dup2(fd, 0);
				close(fd);
				goto out;
			}
			if (errno != EAGAIN) {
				fatalperror(2, "accept");
			}
		}
	}

out:
	for (i = 0, fdp = fds; i < nfds; i++, fdp++) {
		close(fdp->fd);
	}
	free(fds);
}

int
main(int argc, char *argv[], char *env[])
{
	struct sockaddr_storage from;
	int on = 1;
	socklen_t fromlen;
	register int ch;
	int i;

#if	defined(HAS_IPPROTO_IP) && defined(IP_TOS)
	int tos = -1;
#endif

	initsetproctitle(argc, argv, env);

	pfrontp = pbackp = ptyobuf;
	netip = netibuf;

#ifdef USE_SSL
	/* we need to know the fullpath to the location of the
	 * certificate that we will be running with as we cannot
	 * be sure of the cwd when we are launched
	 */
	sprintf(cert_filepath,"%s/%s",X509_get_default_cert_dir(),
	        "telnetd.pem");
	ssl_cert_file=cert_filepath;
	ssl_key_file=NULL;
#endif /* USE_SSL */

	while ((ch = getopt(argc, argv, "d:a:e:lhnNr:I:D:B:sS:a:X:L:z:")) != EOF) {
		switch(ch) {

#ifdef USE_SSL
                case 'z':
		        { 
			char *origopt;

			origopt=strdup(optarg);
			optarg=strtok(origopt,",");

			while(optarg!=NULL) {

		        if (strcmp(optarg, "debug") == 0 ) {
			    ssl_debug_flag=1;
			} else if (strcmp(optarg, "ssl") == 0 ) {
			    ssl_only_flag=1;
			} else if (strcmp(optarg, "certsok") == 0 ) {
			    ssl_certsok_flag=1;
			} else if ( (strcmp(optarg, "!ssl") == 0) ||
		             (strcmp(optarg, "nossl") == 0) ) {
			    /* we may want to switch SSL negotiation off
			     * for testing or other reasons 
			     */
			    ssl_disabled_flag=1;
			} else if (strcmp(optarg, "certrequired") == 0 ) {
			    ssl_cert_required=1;
			} else if (strcmp(optarg, "secure") == 0 ) {
			    ssl_secure_flag=1;
			} else if (strncmp(optarg, "verify=", 
			                strlen("verify=")) == 0 ) {
			    ssl_verify_flag=atoi(optarg+strlen("verify="));
			} else if (strncmp(optarg, "cert=", 
			                strlen("cert=")) == 0 ) {
			    ssl_cert_file=optarg+strlen("cert=");
			} else if (strncmp(optarg, "key=", 
			                strlen("key=")) == 0 ) {
			    ssl_key_file=optarg+strlen("key=");
			} else if (strncmp(optarg,"cipher=",
			                strlen("cipher="))==0) {
			    ssl_cipher_list=optarg+strlen("cipher=");
			} else {
			    /* report when we are given rubbish so that
			     * if the user makes a mistake they have to
			     * correct it!
			     */
			    fprintf(stderr,"Unknown SSL option %s\n",optarg);
			    fflush(stderr);
			    exit(1);
			}

			/* get the next one ... */
                        optarg=strtok(NULL,",");

			}

			/*
			if (origopt!=NULL)
			    free(origopt);
			*/

			}
			break;
#endif /* USE_SSL */

#ifdef	AUTHENTICATE
		case 'a':
			/*
			 * Check for required authentication level
			 */
			if (strcmp(optarg, "debug") == 0) {
				extern int auth_debug_mode;
				auth_debug_mode = 1;
			} else if (strcasecmp(optarg, "none") == 0) {
				auth_level = 0;
			} else if (strcasecmp(optarg, "other") == 0) {
				auth_level = AUTH_OTHER;
			} else if (strcasecmp(optarg, "user") == 0) {
				auth_level = AUTH_USER;
			} else if (strcasecmp(optarg, "valid") == 0) {
				auth_level = AUTH_VALID;
			} else if (strcasecmp(optarg, "off") == 0) {
				/*
				 * This hack turns off authentication
				 */
				auth_level = -1;
			} else {
				fprintf(stderr,
			    "telnetd: unknown authorization level for -a\n");
			}
			break;
#endif	/* AUTHENTICATE */

#ifdef BFTPDAEMON
		case 'B':
			bftpd++;
			break;
#endif /* BFTPDAEMON */

		case 'd':
			if (strcmp(optarg, "ebug") == 0) {
				debug++;
				break;
			}
			usage();
			/* NOTREACHED */
			break;

#ifdef DIAGNOSTICS
		case 'D':
			/*
			 * Check for desired diagnostics capabilities.
			 */
			if (!strcmp(optarg, "report")) {
				diagnostic |= TD_REPORT|TD_OPTIONS;
			} else if (!strcmp(optarg, "exercise")) {
				diagnostic |= TD_EXERCISE;
			} else if (!strcmp(optarg, "netdata")) {
				diagnostic |= TD_NETDATA;
			} else if (!strcmp(optarg, "ptydata")) {
				diagnostic |= TD_PTYDATA;
			} else if (!strcmp(optarg, "options")) {
				diagnostic |= TD_OPTIONS;
			} else {
				usage();
				/* NOT REACHED */
			}
			break;
#endif /* DIAGNOSTICS */

#ifdef	AUTHENTICATE
		case 'e':
			if (strcmp(optarg, "debug") == 0) {
				extern int auth_debug_mode;
				auth_debug_mode = 1;
				break;
			}
			usage();
			/* NOTREACHED */
			break;
#endif	/* AUTHENTICATE */

		case 'h':
			hostinfo = 0;
			break;

#ifdef	LINEMODE
		case 'l':
			alwayslinemode = 1;
			break;
#endif	/* LINEMODE */

		case 'L':
			loginprg = strdup(optarg);
			/* XXX what if strdup fails? */
			break;

		case 'n':
			keepalive = 0;
			break;

		case 'N':
		  numeric_hosts = 1;
		  break;

#ifdef	SecurID
		case 's':
			/* SecurID required */
			require_SecurID = 1;
			break;
#endif	/* SecurID */
		case 'S':
#ifdef	HAS_GETTOS
			if ((tos = parsetos(optarg, "tcp")) < 0)
				fprintf(stderr, "%s%s%s\n",
					"telnetd: Bad TOS argument '", optarg,
					"'; will try to use default TOS");
#else
			fprintf(stderr, "%s%s\n", "TOS option unavailable; ",
						"-S flag not supported\n");
#endif
			break;

#ifdef	AUTHENTICATE
		case 'X':
			/*
			 * Check for invalid authentication types
			 */
			auth_disable_name(optarg);
			break;
#endif	/* AUTHENTICATE */

		default:
			fprintf(stderr, "telnetd: %c: unknown option\n", ch);
			/* FALLTHROUGH */
		case '?':
			usage();
			/* NOTREACHED */
		}
	}

#ifdef USE_SSL

        if (ssl_secure_flag || ssl_cert_required || ssl_certsok_flag) {
	    /* in secure mode we *must* switch on the base level
	     * verify checking otherwise we cannot abort connections
	     * at the right place!
	     */
	    if (ssl_verify_flag==0)
		ssl_verify_flag=1;
	}

	/* if we are not running in debug then any error
	 * stuff from SSL debug *must* not go down
	 * the socket (which 0,1,2 are all pointing to by
	 * default)
	 */
	if (ssl_debug_flag)
	    ssl_log_file="/telnetd.log";

	if (!do_ssleay_init(1)) {
	  if (bio_err!=NULL) {
	    BIO_printf(bio_err,"do_ssleay_init() failed\n");
	    ERR_print_errors(bio_err);
	  } else {
	    fflush(stderr);
	    fprintf(stderr,"do_ssleay_init() failed\n");
	    ERR_print_errors_fp(stderr);
	  }
	  exit(1);
	}

	if (ssl_debug_flag) {
	  BIO_printf(bio_err,"secure %d certrequired %d verify %d\n",
	      ssl_secure_flag,ssl_cert_required,ssl_verify_flag);
	  for(i=0;i<argc;i++)
	      BIO_printf(bio_err,"argv[%d]=\"%s\"\n",i,argv[i]);
	}

#endif /* USE_SSL */

	argc -= optind;
	argv += optind;

	if (debug) {
		if (argc > 1) {
			usage();
			/* NOTREACHED */
		}

		wait_for_connection((argc == 1) ? *argv : "telnet");
	}

	openlog("telnetd", LOG_PID | LOG_ODELAY, LOG_DAEMON);
	fromlen = sizeof (from);
	if (getpeername(0, (struct sockaddr *)&from, &fromlen) < 0) {
		fatalperror(2, "getpeername");
	}
	if (keepalive &&
	    setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof (on)) < 0) {
		syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
	}

#if	defined(HAS_IPPROTO_IP) && defined(IP_TOS)
	{
# if	defined(HAS_GETTOS)
		struct tosent *tp;
		if (tos < 0 && (tp = gettosbyname("telnet", "tcp")))
			tos = tp->t_tos;
# endif
		if (tos < 0)
			tos = 020;	/* Low Delay bit */
		if (tos
		   && (setsockopt(0, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0)
		   && (errno != ENOPROTOOPT) )
			syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
	}
#endif	/* defined(HAS_IPPROTO_IP) && defined(IP_TOS) */

#ifdef USE_SSL
        /* do the SSL stuff now ... before we play with pty's */
	SSL_set_fd(ssl_con,0);

	if (ssl_only_flag) {
	    /* hmm ... only when running talking to things like
	     * https servers should we hit this code and then
	     * we really don't care *who* we talk to :-)
	     */
	    SSL_set_verify(ssl_con,ssl_verify_flag,NULL);

	    if (SSL_accept(ssl_con) <= 0) {
		static char errbuf[1024];
	    
	        sprintf(errbuf,"SSL_accept error %s\n",
		    ERR_error_string(ERR_get_error(),NULL));

		syslog(LOG_WARNING, "%s", errbuf);

		BIO_printf(bio_err,"%s",errbuf);

		/* go to sleep to make sure we are noticed */
		sleep(10);
		SSL_free(ssl_con);

		_exit(1);
	    } else {
		ssl_active_flag=1;
	    }
	}
#endif /* USE_SSL */

	net = 0;
	netopen();
	doit((struct sockaddr *)&from, fromlen);
	/* NOTREACHED */
	return 0;
}  /* end of main */

void
usage(void)
{
	fprintf(stderr, "Usage: telnetd");
#ifdef	AUTHENTICATE
	fprintf(stderr, " [-a (debug|other|user|valid|off)]\n\t");
#endif
#ifdef BFTPDAEMON
	fprintf(stderr, " [-B]");
#endif
	fprintf(stderr, " [-debug port]");
#ifdef DIAGNOSTICS
	fprintf(stderr, " [-D (options|report|exercise|netdata|ptydata)]\n\t");
#endif
#ifdef	AUTHENTICATE
	fprintf(stderr, " [-edebug]");
#endif
	fprintf(stderr, " [-h]");
#ifdef LINEMODE
	fprintf(stderr, " [-l]");
#endif
	fprintf(stderr, " [-L login_program]");
	fprintf(stderr, " [-n]");
#ifdef	SecurID
	fprintf(stderr, " [-s]");
#endif
#ifdef	AUTHENTICATE
	fprintf(stderr, " [-X auth-type]");
#endif
#ifdef USE_SSL
        /* might as well output something useful here ... */
	fprintf(stderr, "\n\t [-z ssl] [-z secure] [-z debug] [-z verify=int]\n\t");
	fprintf(stderr, " [-z cert=file] [-z key=file]\n\t");
#endif /* USE_SSL */
	fprintf(stderr, "\n");
	exit(1);
}

/*
 * getterminaltype
 *
 *	Ask the other end to send along its terminal type and speed.
 * Output is the variable terminaltype filled in.
 */

static void _gettermname(void);

static
int
getterminaltype(char *name)
{
    int retval = -1;
    (void)name;

    settimer(baseline);
#if defined(AUTHENTICATE)
    /*
     * Handle the Authentication option before we do anything else.
     */
    send_do(TELOPT_ENVIRON, 1);
    while (his_will_wont_is_changing(TELOPT_ENVIRON)) {
	ttloop();
    }

    if (his_state_is_will(TELOPT_ENVIRON)) {
      netoprintf("%c%c%c%c%c%c", 
		 IAC, SB, TELOPT_ENVIRON, TELQUAL_SEND, IAC, SE);
	while (sequenceIs(environsubopt, baseline))
	    ttloop();
    }

    send_do(TELOPT_AUTHENTICATION, 1);
    while (his_will_wont_is_changing(TELOPT_AUTHENTICATION))
	ttloop();
    if (his_state_is_will(TELOPT_AUTHENTICATION)) {
	retval = auth_wait(name);
    }

#ifdef USE_SSL
    /* if SSL is required then we will stop if we don't
     * have it *now*
     */
    if (ssl_secure_flag) {
	if (!ssl_active_flag) {
	    /* we need to indicate to the user that SSL
	     * is required ... need to think about how
	     * to do this cleanly at this point!
	     */

#if 0
            /* this muck is needed so that the message
	     * actually makes it back to the user ...
	     */
	    send_do(TELOPT_TTYPE, 1);
	    send_do(TELOPT_TSPEED, 1);
	    send_do(TELOPT_XDISPLOC, 1);
	    send_do(TELOPT_ENVIRON, 1);

	    while (
#if	defined(ENCRYPT)
		   his_do_dont_is_changing(TELOPT_ENCRYPT) ||
#endif
		   his_will_wont_is_changing(TELOPT_TTYPE) ||
		   his_will_wont_is_changing(TELOPT_TSPEED) ||
		   his_will_wont_is_changing(TELOPT_XDISPLOC) ||
		   his_will_wont_is_changing(TELOPT_ENVIRON)) {
		ttloop();
	    }
#endif

            if (ssl_debug_flag) {
		fprintf(stderr,"[SSL required - connection rejected]");
		fflush(stderr);
	    }

	    fatal(net,"[SSL required - connection rejected]");

	}
    }
#endif /* USE_SSL */

#endif

#if	defined(ENCRYPT)
    send_will(TELOPT_ENCRYPT, 1);
#endif
    send_do(TELOPT_TTYPE, 1);
    send_do(TELOPT_TSPEED, 1);
    send_do(TELOPT_XDISPLOC, 1);
    while (
#if	defined(ENCRYPT)
	   his_do_dont_is_changing(TELOPT_ENCRYPT) ||
#endif
	   his_will_wont_is_changing(TELOPT_TTYPE) ||
	   his_will_wont_is_changing(TELOPT_TSPEED) ||
	   his_will_wont_is_changing(TELOPT_XDISPLOC) ||
	   his_will_wont_is_changing(TELOPT_ENVIRON)) {
	ttloop();
    }
#if	defined(ENCRYPT)
    /*
     * Wait for the negotiation of what type of encryption we can
     * send with.  If autoencrypt is not set, this will just return.
     */
    if (his_state_is_will(TELOPT_ENCRYPT)) {
	encrypt_wait();
    }
#endif
    if (his_state_is_will(TELOPT_TSPEED)) {
	netoprintf("%c%c%c%c%c%c", 
		   IAC, SB, TELOPT_TSPEED, TELQUAL_SEND, IAC, SE);
    }
    if (his_state_is_will(TELOPT_XDISPLOC)) {
	netoprintf("%c%c%c%c%c%c", 
		   IAC, SB, TELOPT_XDISPLOC, TELQUAL_SEND, IAC, SE);
    }
    if (his_state_is_will(TELOPT_ENVIRON)) {
	netoprintf("%c%c%c%c%c%c", 
		   IAC, SB, TELOPT_ENVIRON, TELQUAL_SEND, IAC, SE);
    }
    if (his_state_is_will(TELOPT_TTYPE)) {
       netoprintf("%c%c%c%c%c%c", 
		  IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE);
    }
    if (his_state_is_will(TELOPT_TSPEED)) {
	while (sequenceIs(tspeedsubopt, baseline))
	    ttloop();
    }
    if (his_state_is_will(TELOPT_XDISPLOC)) {
	while (sequenceIs(xdisplocsubopt, baseline))
	    ttloop();
    }
    if (his_state_is_will(TELOPT_TTYPE)) {
	char first[256], last[256];

	while (sequenceIs(ttypesubopt, baseline))
	    ttloop();

	/*
	 * If the other side has already disabled the option, then
	 * we have to just go with what we (might) have already gotten.
	 */
	if (his_state_is_will(TELOPT_TTYPE) && !terminaltypeok(terminaltype)) {
	    /*
	     * Due to state.c, terminaltype points to a static char[41].
	     * Therefore, this assert cannot fail, and therefore, strings
	     * arising from "terminaltype" can be safely strcpy'd into
	     * first[] or last[].
	     */
	    assert(strlen(terminaltype) < sizeof(first));

	    strcpy(first, terminaltype);

	    for(;;) {
		/*
		 * Save the unknown name, and request the next name.
		 */
		strcpy(last, terminaltype);

		_gettermname();
		assert(strlen(terminaltype) < sizeof(first));

		if (terminaltypeok(terminaltype))
		    break;

		if (!strcmp(last, terminaltype) ||
		    his_state_is_wont(TELOPT_TTYPE)) {
		    /*
		     * We've hit the end.  If this is the same as
		     * the first name, just go with it.
		     */
		    if (!strcmp(first, terminaltype))
			break;
		    /*
		     * Get the terminal name one more time, so that
		     * RFC1091 compliant telnets will cycle back to
		     * the start of the list.
		     */
		     _gettermname();
		    assert(strlen(terminaltype) < sizeof(first));

		    if (strcmp(first, terminaltype)) {
			/*
			 * first[] came from terminaltype, so it must fit
			 * back in.
			 */
			strcpy(terminaltype, first);
		    }
		    break;
		}
	    }
	}
    }
    return(retval);
}  /* end of getterminaltype */

static
void
_gettermname(void)
{
    /*
     * If the client turned off the option,
     * we can't send another request, so we
     * just return.
     */
    if (his_state_is_wont(TELOPT_TTYPE))
	return;

    settimer(baseline);
    netoprintf("%c%c%c%c%c%c", IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE);
    while (sequenceIs(ttypesubopt, baseline))
	ttloop();
}

static int
terminaltypeok(const char *s)
{
    /* char buf[2048]; */

    if (terminaltype == NULL)
	return(1);

    /*
     * Fix from Chris Evans: if it has a / in it, termcap will
     * treat it as a filename. Oops.
     */
    if (strchr(s, '/')) {
	return 0;
    }

    /*
     * If it's absurdly long, accept it without asking termcap.
     *
     * This means that it won't get seen again until after login,
     * at which point exploiting buffer problems in termcap doesn't
     * gain one anything.
     *
     * It's possible this limit ought to be raised to 128, but nothing
     * in my termcap is more than 64, 64 is _plenty_ for most, and while
     * buffers aren't likely to be smaller than 64, they might be 80 and
     * thus less than 128.
     */
    if (strlen(s) > 63) {
       return 0;
    }

    /*
     * tgetent() will return 1 if the type is known, and
     * 0 if it is not known.  If it returns -1, it couldn't
     * open the database.  But if we can't open the database,
     * it won't help to say we failed, because we won't be
     * able to verify anything else.  So, we treat -1 like 1.
     */

    /*
     * Don't do this - tgetent is not really trustworthy. Assume
     * the terminal type is one we know; terminal types are pretty
     * standard now. And if it isn't, it's unlikely we're going to
     * know anything else the remote telnet might send as an alias
     * for it.
     *
     * if (tgetent(buf, s) == 0)
     *    return(0);
     */
    return(1);
}

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 64
#endif	/* MAXHOSTNAMELEN */

char host_name[MAXHOSTNAMELEN];
char remote_host_name[MAXHOSTNAMELEN];

extern void telnet(int, int);

/*
 * Get a pty, scan input lines.
 */
static void
doit(struct sockaddr *who, socklen_t who_len)
{
	char *host;
	int level;
	char user_name[256];
	int i;
	struct addrinfo hints, *res;

	/*
	 * Find an available pty to use.
	 */
	pty = getpty();
	if (pty < 0)
		fatalperror(net, "getpty");

	/* get name of connected client */
	if (getnameinfo(who, who_len, remote_host_name,
			sizeof(remote_host_name), 0, 0, 
			numeric_hosts ? NI_NUMERICHOST : 0)) {
		syslog(LOG_ERR, "doit: getnameinfo: %m");
		*remote_host_name = 0;
        }

	/* Disallow funnies. */
	for (i=0; remote_host_name[i]; i++) {
	    if (remote_host_name[i]<=32 || remote_host_name[i]>126) 
		remote_host_name[i] = '?';
	}
	host = remote_host_name;

	/* Get local host name */
	gethostname(host_name, sizeof(host_name));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_CANONNAME;
	if ((i = getaddrinfo(host_name, 0, &hints, &res)))
		syslog(LOG_WARNING, "doit: getaddrinfo: %s", gai_strerror(i));
	else {
		strncpy(host_name, res->ai_canonname, sizeof(host_name)-1);
		host_name[sizeof(host_name)-1] = 0;
	}

#if	defined(AUTHENTICATE) || defined(ENCRYPT)
	auth_encrypt_init(host_name, host, "TELNETD", 1);
#endif

	init_env();
	/*
	 * get terminal type.
	 */
	*user_name = 0;
	level = getterminaltype(user_name);
	setenv("TERM", terminaltype ? terminaltype : "network", 1);

	/* TODO list stuff provided by Laszlo Vecsey <master@internexus.net> */

#ifdef USE_SSL
	if (debug) {
	    fprintf(stderr,"doit - ALIVE\n");
	    fflush(stderr);
	    sleep(2);
	}
#endif /* USE_SSL */


	/*
	 * Set REMOTEHOST environment variable
	 */
	setproctitle("%s", host);
	setenv("REMOTEHOST", host, 0);

#ifdef USE_SSL
	if (debug) {
	    fprintf(stderr,"doit - starting telnet protocol itself\n");
	    fflush(stderr);
	    sleep(2);
	}
#endif /* USE_SSL */

	/*
	 * Start up the login process on the slave side of the terminal
	 */
	startslave(host, level, user_name);

	telnet(net, pty);  /* begin server processing */

	/*NOTREACHED*/
}  /* end of doit */

/*
 * Main loop.  Select from pty and network, and
 * hand data to telnet receiver finite state machine.
 */
void telnet(int f, int p)
{
    int on = 1;
    char *HE;
    const char *IM;

    /*
     * Initialize the slc mapping table.
     */
    get_slc_defaults();

    /*
     * Do some tests where it is desireable to wait for a response.
     * Rather than doing them slowly, one at a time, do them all
     * at once.
     */
    if (my_state_is_wont(TELOPT_SGA))
	send_will(TELOPT_SGA, 1);
    /*
     * Is the client side a 4.2 (NOT 4.3) system?  We need to know this
     * because 4.2 clients are unable to deal with TCP urgent data.
     *
     * To find out, we send out a "DO ECHO".  If the remote system
     * answers "WILL ECHO" it is probably a 4.2 client, and we note
     * that fact ("WILL ECHO" ==> that the client will echo what
     * WE, the server, sends it; it does NOT mean that the client will
     * echo the terminal input).
     */
    send_do(TELOPT_ECHO, 1);
    
#ifdef	LINEMODE
    if (his_state_is_wont(TELOPT_LINEMODE)) {
	/*
	 * Query the peer for linemode support by trying to negotiate
	 * the linemode option.
	 */
	linemode = 0;
	editmode = 0;
	send_do(TELOPT_LINEMODE, 1);  /* send do linemode */
    }
#endif	/* LINEMODE */

    /*
     * Send along a couple of other options that we wish to negotiate.
     */
    send_do(TELOPT_NAWS, 1);
    send_will(TELOPT_STATUS, 1);
    flowmode = 1;  /* default flow control state */
    send_do(TELOPT_LFLOW, 1);
    
    /*
     * Spin, waiting for a response from the DO ECHO.  However,
     * some REALLY DUMB telnets out there might not respond
     * to the DO ECHO.  So, we spin looking for NAWS, (most dumb
     * telnets so far seem to respond with WONT for a DO that
     * they don't understand...) because by the time we get the
     * response, it will already have processed the DO ECHO.
     * Kludge upon kludge.
     */
    while (his_will_wont_is_changing(TELOPT_NAWS)) {
	ttloop();
    }
    
    /*
     * But...
     * The client might have sent a WILL NAWS as part of its
     * startup code; if so, we'll be here before we get the
     * response to the DO ECHO.  We'll make the assumption
     * that any implementation that understands about NAWS
     * is a modern enough implementation that it will respond
     * to our DO ECHO request; hence we'll do another spin
     * waiting for the ECHO option to settle down, which is
     * what we wanted to do in the first place...
     */
    if (his_want_state_is_will(TELOPT_ECHO) &&
	his_state_is_will(TELOPT_NAWS)) {
	while (his_will_wont_is_changing(TELOPT_ECHO))
	    ttloop();
    }
    /*
     * On the off chance that the telnet client is broken and does not
     * respond to the DO ECHO we sent, (after all, we did send the
     * DO NAWS negotiation after the DO ECHO, and we won't get here
     * until a response to the DO NAWS comes back) simulate the
     * receipt of a will echo.  This will also send a WONT ECHO
     * to the client, since we assume that the client failed to
     * respond because it believes that it is already in DO ECHO
     * mode, which we do not want.
     */
    if (his_want_state_is_will(TELOPT_ECHO)) {
	DIAG(TD_OPTIONS, netoprintf("td: simulating recv\r\n"););
	willoption(TELOPT_ECHO);
    }
    
    /*
     * Finally, to clean things up, we turn on our echo.  This
     * will break stupid 4.2 telnets out of local terminal echo.
     */
    
    if (my_state_is_wont(TELOPT_ECHO))
	send_will(TELOPT_ECHO, 1);
    
    /*
     * Turn on packet mode
     */
    ioctl(p, TIOCPKT, (char *)&on);
#if defined(LINEMODE) && defined(KLUDGELINEMODE)
    /*
     * Continuing line mode support.  If client does not support
     * real linemode, attempt to negotiate kludge linemode by sending
     * the do timing mark sequence.
     */
    if (lmodetype < REAL_LINEMODE)
	send_do(TELOPT_TM, 1);
#endif	/* defined(LINEMODE) && defined(KLUDGELINEMODE) */
    
    /*
     * Call telrcv() once to pick up anything received during
     * terminal type negotiation, 4.2/4.3 determination, and
     * linemode negotiation.
     */
    telrcv();
    
#ifndef USE_SSL
    ioctl(f, FIONBIO, (char *)&on);
#endif /* !USE_SSL */

    ioctl(p, FIONBIO, (char *)&on);

#if defined(SO_OOBINLINE)
    setsockopt(net, SOL_SOCKET, SO_OOBINLINE, &on, sizeof on);
#endif	/* defined(SO_OOBINLINE) */
    
#ifdef	SIGTSTP
    signal(SIGTSTP, SIG_IGN);
#endif
#ifdef	SIGTTOU
    /*
     * Ignoring SIGTTOU keeps the kernel from blocking us
     * in ttioct() in /sys/tty.c.
     */
    signal(SIGTTOU, SIG_IGN);
#endif
    
    signal(SIGCHLD, cleanup);
    
#ifdef TIOCNOTTY
    {
	register int t;
	t = open(_PATH_TTY, O_RDWR);
	if (t >= 0) {
	    (void) ioctl(t, TIOCNOTTY, (char *)0);
	    (void) close(t);
	}
    }
#endif
    
    /*
     * Show banner that getty never gave.
     *
     * We put the banner in the pty input buffer.  This way, it
     * gets carriage return null processing, etc., just like all
     * other pty --> client data.
     */
    
    if (getenv("USER"))
	hostinfo = 0;
    
    IM = DEFAULT_IM;
    HE = 0;

    edithost(HE, host_name);
    if (hostinfo && *IM)
	putf(IM, ptyibuf2);
    
    if (pcc) strncat(ptyibuf2, ptyip, pcc+1);
    ptyip = ptyibuf2;
    pcc = strlen(ptyip);
#ifdef LINEMODE
    /*
     * Last check to make sure all our states are correct.
     */
    init_termbuf();
    localstat();
#endif	/* LINEMODE */

    DIAG(TD_REPORT, netoprintf("td: Entering processing loop\r\n"););
    
    for (;;) {
	fd_set ibits, obits, xbits;
	int c, hifd;
	
	if (ncc < 0 && pcc < 0)
	    break;
	
	FD_ZERO(&ibits);
	FD_ZERO(&obits);
	FD_ZERO(&xbits);
	hifd=0;
	/*
	 * Never look for input if there's still
	 * stuff in the corresponding output buffer
	 */
	if (netbuflen(1) || pcc > 0) {
	    FD_SET(f, &obits);
	    if (f >= hifd) hifd = f+1;
	} 
	else {
	    FD_SET(p, &ibits);
	    if (p >= hifd) hifd = p+1;
	}
	if (pfrontp - pbackp || ncc > 0) {
	    FD_SET(p, &obits);
	    if (p >= hifd) hifd = p+1;
	} 
	else {
	    FD_SET(f, &ibits);
	    if (f >= hifd) hifd = f+1;
	}
	if (!SYNCHing) {
	    FD_SET(f, &xbits);
	    if (f >= hifd) hifd = f+1;
	}
	if ((c = select(hifd, &ibits, &obits, &xbits,
			(struct timeval *)0)) < 1) {
	    if (c == -1) {
		if (errno == EINTR) {
		    continue;
		}
	    }
	    sleep(5);
	    continue;
	}
	
	/*
	 * Any urgent data?
	 */
	if (FD_ISSET(net, &xbits)) {
	    SYNCHing = 1;
	}
	
	/*
	 * Something to read from the network...
	 */
	if (FD_ISSET(net, &ibits)) {
#if !defined(SO_OOBINLINE)
	    /*
	     * In 4.2 (and 4.3 beta) systems, the
	     * OOB indication and data handling in the kernel
	     * is such that if two separate TCP Urgent requests
	     * come in, one byte of TCP data will be overlaid.
	     * This is fatal for Telnet, but we try to live
	     * with it.
	     *
	     * In addition, in 4.2 (and...), a special protocol
	     * is needed to pick up the TCP Urgent data in
	     * the correct sequence.
	     *
	     * What we do is:  if we think we are in urgent
	     * mode, we look to see if we are "at the mark".
	     * If we are, we do an OOB receive.  If we run
	     * this twice, we will do the OOB receive twice,
	     * but the second will fail, since the second
	     * time we were "at the mark", but there wasn't
	     * any data there (the kernel doesn't reset
	     * "at the mark" until we do a normal read).
	     * Once we've read the OOB data, we go ahead
	     * and do normal reads.
	     *
	     * There is also another problem, which is that
	     * since the OOB byte we read doesn't put us
	     * out of OOB state, and since that byte is most
	     * likely the TELNET DM (data mark), we would
	     * stay in the TELNET SYNCH (SYNCHing) state.
	     * So, clocks to the rescue.  If we've "just"
	     * received a DM, then we test for the
	     * presence of OOB data when the receive OOB
	     * fails (and AFTER we did the normal mode read
	     * to clear "at the mark").
	     */
#ifndef USE_SSL
	    if (SYNCHing) {
		int atmark;
		
		ioctl(net, SIOCATMARK, (char *)&atmark);
		if (atmark) {
		    ncc = recv(net, netibuf, sizeof (netibuf), MSG_OOB);
		    if ((ncc == -1) && (errno == EINVAL)) {
			ncc = read(net, netibuf, sizeof (netibuf));
			if (sequenceIs(didnetreceive, gotDM)) {
			    SYNCHing = stilloob(net);
			}
		    }
		} 
		else {
		    ncc = read(net, netibuf, sizeof (netibuf));
		}
	    } 
	    else
#endif /* !USE_SSL */
	    {
#ifdef USE_SSL
			if (ssl_active_flag)
			    ncc = SSL_read(ssl_con, netibuf, sizeof (netibuf));
			else
#endif /* USE_SSL */
		ncc = read(net, netibuf, sizeof (netibuf));
	    }
	    settimer(didnetreceive);
#else	/* !defined(SO_OOBINLINE)) */
#ifdef USE_SSL
		    if (ssl_active_flag)
			ncc = SSL_read(ssl_con, netibuf, sizeof (netibuf));
		    else
#endif /* USE_SSL */
	    ncc = read(net, netibuf, sizeof (netibuf));
#endif	/* !defined(SO_OOBINLINE)) */
	    if (ncc < 0 && errno == EWOULDBLOCK)
		ncc = 0;
	    else {
		if (ncc <= 0) {
		    break;
		}
		netip = netibuf;
	    }
	    DIAG((TD_REPORT | TD_NETDATA),
		 netoprintf("td: netread %d chars\r\n", ncc););
	    DIAG(TD_NETDATA, printdata("nd", netip, ncc));
	}
	
	/*
	 * Something to read from the pty...
	 */
	if (FD_ISSET(p, &ibits)) {
	    pcc = read(p, ptyibuf, BUFSIZ);
	    /*
	     * On some systems, if we try to read something
	     * off the master side before the slave side is
	     * opened, we get EIO.
	     */
	    if (pcc < 0 && (errno == EWOULDBLOCK || errno == EIO)) {
		pcc = 0;
	    } 
	    else {
		if (pcc <= 0)
		    break;
#ifdef	LINEMODE
				/*
				 * If ioctl from pty, pass it through net
				 */
		if (ptyibuf[0] & TIOCPKT_IOCTL) {
		    copy_termbuf(ptyibuf+1, pcc-1);
		    localstat();
		    pcc = 1;
		}
#endif	/* LINEMODE */
		if (ptyibuf[0] & TIOCPKT_FLUSHWRITE) {
		    static const char msg[] = { IAC, DM };
		    netclear();	/* clear buffer back */
#ifndef	NO_URGENT
		    /*
		     * There are client telnets on some
		     * operating systems get screwed up
		     * royally if we send them urgent
		     * mode data.
		     */
		    sendurg(msg, sizeof(msg));
#endif
		}
		if (his_state_is_will(TELOPT_LFLOW) &&
		    (ptyibuf[0] &
		     (TIOCPKT_NOSTOP|TIOCPKT_DOSTOP))) {
			netoprintf("%c%c%c%c%c%c",
				   IAC, SB, TELOPT_LFLOW,
				   ptyibuf[0] & TIOCPKT_DOSTOP ? 1 : 0,
				   IAC, SE);
		}
		pcc--;
		ptyip = ptyibuf+1;
	    }
	}
	
	while (pcc > 0 && !netbuflen(0)) {
	    c = *ptyip++ & 0377, pcc--;
	    if (c == IAC)
		putc(c, netfile);
	    putc(c, netfile);
	    if ((c == '\r'  ) && (my_state_is_wont(TELOPT_BINARY))) {
		if (pcc > 0 && ((*ptyip & 0377) == '\n')) {
		    putc(*ptyip++ & 0377, netfile);
		    pcc--;
		} 
		else putc('\0', netfile);
	    }
	}

	if (FD_ISSET(f, &obits))
	    netflush();
	if (ncc > 0)
	    telrcv();
	if (FD_ISSET(p, &obits) && (pfrontp - pbackp) > 0)
	    ptyflush();
    }
    cleanup(0);
}  /* end of telnet */
	
#ifndef	TCSIG
# ifdef	TIOCSIG
#  define TCSIG TIOCSIG
# endif
#endif

/*
 * Send interrupt to process on other side of pty.
 * If it is in raw mode, just write NULL;
 * otherwise, write intr char.
 */
void interrupt(void) {
    ptyflush();	/* half-hearted */
    
#ifdef	TCSIG
    (void) ioctl(pty, TCSIG, (char *)SIGINT);
#else	/* TCSIG */
    init_termbuf();
    *pfrontp++ = slctab[SLC_IP].sptr ?
	 (unsigned char)*slctab[SLC_IP].sptr : '\177';
#endif	/* TCSIG */
}

/*
 * Send quit to process on other side of pty.
 * If it is in raw mode, just write NULL;
 * otherwise, write quit char.
 */
void sendbrk(void) {
    ptyflush();	/* half-hearted */
#ifdef	TCSIG
    (void) ioctl(pty, TCSIG, (char *)SIGQUIT);
#else	/* TCSIG */
    init_termbuf();
    *pfrontp++ = slctab[SLC_ABORT].sptr ?
	 (unsigned char)*slctab[SLC_ABORT].sptr : '\034';
#endif	/* TCSIG */
}

void sendsusp(void) {
#ifdef	SIGTSTP
    ptyflush();	/* half-hearted */
# ifdef	TCSIG
    (void) ioctl(pty, TCSIG, (char *)SIGTSTP);
# else	/* TCSIG */
    *pfrontp++ = slctab[SLC_SUSP].sptr ?
	(unsigned char)*slctab[SLC_SUSP].sptr : '\032';
# endif	/* TCSIG */
#endif	/* SIGTSTP */
}

/*
 * When we get an AYT, if ^T is enabled, use that.  Otherwise,
 * just send back "[Yes]".
 */
void recv_ayt(void) {
#if	defined(SIGINFO) && defined(TCSIG)
    if (slctab[SLC_AYT].sptr && *slctab[SLC_AYT].sptr != _POSIX_VDISABLE) {
	(void) ioctl(pty, TCSIG, (char *)SIGINFO);
	return;
    }
#endif
    netoprintf("\r\n[%s : yes]\r\n", host_name);
}

void doeof(void) {
    init_termbuf();

#if	defined(LINEMODE) && (VEOF == VMIN)
    if (!tty_isediting()) {
	extern char oldeofc;
	*pfrontp++ = oldeofc;
	return;
    }
#endif
    *pfrontp++ = slctab[SLC_EOF].sptr ?
	     (unsigned char)*slctab[SLC_EOF].sptr : '\004';
}
