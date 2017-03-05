/*
 * Copyright (c) 1988, 1990 Regents of the University of California.
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
  "@(#) Copyright (c) 1988, 1990 Regents of the University of California.\n"
  "All rights reserved.\n";

/*
 * From: @(#)main.c	5.4 (Berkeley) 3/22/91
 */
char main_rcsid[] = 
  "$Id: main.cc,v 1.6 2004-11-22 20:26:37 ianb Exp $";

#include "../version.h"

#include <sys/types.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include "ring.h"
#include "externs.h"
#include "defines.h"
#include "proto.h"

#if defined(AUTHENTICATE)
#include <libtelnet/auth.h>
#include <libtelnet/misc.h>
#endif

/*
 * Initialize variables.
 */
void
tninit(void)
{
    init_terminal();

    init_network();
    
    init_telnet();

    init_sys();

#if defined(TN3270)
    init_3270();
#endif
}

/*
 * note: -x should mean use encryption
 *       -k <realm> to set kerberos realm
 *       -K don't auto-login
 *       -X <atype> disable specified auth type
 */ 
void usage(void) {
    fprintf(stderr, "Usage: %s %s%s%s%s%s\n",
	    prompt,
#ifdef	AUTHENTICATE
	    "[-4] [-6] [-8] [-E] [-K] [-L] [-X atype] [-a] [-d] [-e char]",
	    "\n\t[-l user] [-n tracefile] [ -b addr ]",
#else
	    "[-4] [-6] [-8] [-E] [-L] [-a] [-d] [-e char] [-l user]",
	    "\n\t[-n tracefile] [ -b addr ]",
#endif
#ifdef TN3270
	    "\n\t"
	    "[-noasynch] [-noasynctty] [-noasyncnet] [-r] [-t transcom]\n\t",
#else
	    " [-r] ",
#endif
#ifdef USE_SSL
        /* might as well output something useful here ... */
	"\n\t[-z ssl] [-z secure] [-z debug] [-z verify=int]\n\t"
	"[-z cacert=file] [-z cert=file] [-z key=file]\n\t",
#else /* !USE_SSL */
        "",
#endif /* USE_SSL */
	    "[host-name [port]]"
	);
	exit(1);
}

/*
 * main.  Parse arguments, invoke the protocol or command parser.
 */

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int ch;
	char *user, *srcaddr;
	int family;

	tninit();		/* Clear out things */
#if	defined(CRAY) && !defined(__STDC__)
	_setlist_init();	/* Work around compiler bug */
#endif

	TerminalSaveState();
	if ((old_tc.c_cflag & (CSIZE|PARENB)) != CS8)
		eight = 0;

	if ((prompt = strrchr(argv[0], '/'))!=NULL)
		++prompt;
	else
		prompt = argv[0];

	user = srcaddr = NULL;
	family = 0;

	rlogin = (strncmp(prompt, "rlog", 4) == 0) ? '~' : _POSIX_VDISABLE;
	autologin = -1;

	while ((ch = getopt(argc, argv,
			    "4678EKLS:X:ab:de:k:l:n:rt:xz:")) != EOF) {
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
			} else if (strcmp(optarg, "authdebug") == 0 ) {
			    auth_debug_mode=1;
			} else if (strcmp(optarg, "ssl") == 0 ) {
			    ssl_only_flag=1;
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
			} else if (strcmp(optarg, "verbose") == 0 ) {
			    ssl_verbose_flag=1;
			} else if (strncmp(optarg, "verify=", 
			                        strlen("verify=")) == 0 ) {
			    ssl_verify_flag=atoi(optarg+strlen("verify="));
			} else if (strncmp(optarg, "cacert=", 
			                        strlen("cacert=")) == 0 ) {
			    ssl_cacert_file= optarg + strlen("cacert=");
			} else if (strncmp(optarg, "cert=", 
			                        strlen("cert=")) == 0 ) {
			    ssl_cert_file= optarg + strlen("cert=");
			} else if (strncmp(optarg, "key=", 
			                        strlen("key=")) == 0 ) {
			    ssl_key_file= optarg + strlen("key=");
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

		case '4':
			family = AF_INET;
			break;
		case '6':
#ifdef AF_INET6
			family = AF_INET6;
#else
			fputs("IPv6 unsupported\n", stderr);
#endif
			break;
		case '7':
			eight = 0;	/* 7-bit ouput and input */
			break;
		case '8':
			binary = 3;	/* binary output and input */
			break;
		case 'E':
			rlogin = escapechar = _POSIX_VDISABLE;
			break;
		case 'K':
#ifdef	AUTHENTICATE
			autologin = 0;
#endif
			break;
		case 'L':
			binary |= 2;	/* binary output only */
			break;
		case 'S':
		    {
			extern int tos;
			int num;

#ifdef	HAS_GETTOS
			if ((num = parsetos(optarg, "tcp")) < 0) {
#else
			errno = 0;
			num = strtol(optarg, 0, 0);
			if (errno) {
#endif
				fprintf(stderr, "%s%s%s%s\n",
					prompt, ": Bad TOS argument '",
					optarg,
					"; will try to use default TOS");
			} else
				tos = num;
		    }
			break;
		case 'X':
#ifdef	AUTHENTICATE
			auth_disable_name(optarg);
#endif
			break;
		case 'a':
			autologin = 1;
			break;
		case 'c':
			skiprc = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'e':
			set_escape_char(optarg);
			break;
		case 'k':
			fprintf(stderr,
				"%s: -k ignored, no Kerberos V4 support.\n",
				prompt);
			break;
		case 'l':
			autologin = 1;
			user = optarg;
			break;
		case 'n':
#ifdef TN3270
			/* distinguish between "-n oasynch" and "-noasynch" */
			if (argv[optind - 1][0] == '-' && argv[optind - 1][1]
			    == 'n' && argv[optind - 1][2] == 'o') {
				if (!strcmp(optarg, "oasynch")) {
					noasynchtty = 1;
					noasynchnet = 1;
				} else if (!strcmp(optarg, "oasynchtty"))
					noasynchtty = 1;
				else if (!strcmp(optarg, "oasynchnet"))
					noasynchnet = 1;
			} else
#endif	/* TN3270 */
				SetNetTrace(optarg);
			break;
		case 'r':
			rlogin = '~';
			break;
		case 't':
#ifdef TN3270
			transcom = tline;
			(void)strcpy(transcom, optarg);
#else
			fprintf(stderr,
			   "%s: Warning: -t ignored, no TN3270 support.\n",
								prompt);
#endif
			break;
		case 'x':
			fprintf(stderr,
				"%s: -x ignored, no encryption support.\n",
				prompt);
			break;
		case 'b':
			srcaddr = optarg;
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	}
	if (autologin == -1)
		autologin = (rlogin == _POSIX_VDISABLE) ? 0 : 1;

#ifdef USE_SSL
	if((ssl_cert_file != NULL) || (ssl_key_file != NULL)) {
	  autologin = 1;
	}

        if (ssl_secure_flag||ssl_cert_required) {
	    /* in secure mode we *must* switch on the base level
	     * verify checking otherwise we cannot abort connections
	     * at the right place!
	     */
	    if (ssl_verify_flag == 0)
		ssl_verify_flag = SSL_VERIFY_PEER;;
	}

	/* client mode ignores SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	   so simulate it using certrequired */
	if(ssl_verify_flag & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
	  ssl_cert_required=1;
	}
	
#endif /* USE_SSL */

	argc -= optind;
	argv += optind;

	if (argc) {
		const char *args[7];
		const char **volatile argp = args;

		if (argc > 2)
			usage();
		*argp++ = prompt;
		if (user) {
			*argp++ = "-l";
			*argp++ = user;
		}
		if (srcaddr) {
			*argp++ = "-b";
			*argp++ = srcaddr;
		}
		if (family) {
			*argp++ = family == AF_INET ? "-4" : "-6";
		}
		*argp++ = argv[0];		/* host */
		if (argc > 1)
			*argp++ = argv[1];	/* port */
		*argp = 0;

		if (sigsetjmp(toplevel, 1) != 0)
			Exit(0);
		if (tn(argp - args, args) == 1)
			return (0);
		else
			return (1);
	}
	(void)sigsetjmp(toplevel, 1);
	for (;;) {
#ifdef TN3270
		if (shell_active)
			shell_continue();
		else
#endif
			command(1, 0, 0);
	}
}
