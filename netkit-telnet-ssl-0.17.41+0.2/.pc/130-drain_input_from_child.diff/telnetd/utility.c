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

/*
 * From: @(#)utility.c	5.8 (Berkeley) 3/22/91
 */
char util_rcsid[] = 
  "$Id: utility.c,v 1.8 2006-09-24 00:48:31 ianb Exp $";

#define PRINTOPTIONS

#include <stdarg.h>
#include <sys/utsname.h>
#include <sys/time.h>

#ifdef AUTHENTICATE
#include <libtelnet/auth.h>
#endif

#include "telnetd.h"

struct buflist {
	struct buflist *next;
	char *buf;
	size_t len;
};

static struct buflist head = { next: &head, buf: 0, len: 0 };
static struct buflist *tail = &head;
static size_t skip;
static int trailing;
static size_t listlen;
static int doclear;
static struct buflist *urg;

int
telnet_spin()
{
    ttloop();
    return(0);
}

/*
 * ttloop
 *
 *	A small subroutine to flush the network output buffer, get some data
 * from the network, and pass it through the telnet state machine.  We
 * also flush the pty input buffer (by dropping its data) if it becomes
 * too full.
 */

void
ttloop(void)
{

    DIAG(TD_REPORT, netoprintf("td: ttloop\r\n"););
		     
    netflush();
#ifdef USE_SSL
    if (ssl_active_flag)
	ncc = SSL_read(ssl_con, netibuf, sizeof netibuf);
    else
#endif /* USE_SSL */
    ncc = read(net, netibuf, sizeof(netibuf));
    if (ncc < 0) {
	syslog(LOG_INFO, "ttloop: read: %m\n");
	exit(1);
    } else if (ncc == 0) {
	syslog(LOG_INFO, "ttloop: peer died: EOF\n");
	exit(1);
    }
    DIAG(TD_REPORT, netoprintf("td: ttloop read %d chars\r\n", ncc););
    netip = netibuf;
    telrcv();			/* state machine */
    if (ncc > 0) {
	pfrontp = pbackp = ptyobuf;
	telrcv();
    }
}  /* end of ttloop */

/*
 * Check a descriptor to see if out of band data exists on it.
 */
int stilloob(int s)		/* socket number */
{
    static struct timeval timeout = { 0, 0 };
    fd_set	excepts;
    int value;

    do {
	FD_ZERO(&excepts);
	FD_SET(s, &excepts);
	value = select(s+1, (fd_set *)0, (fd_set *)0, &excepts, &timeout);
    } while ((value == -1) && (errno == EINTR));

    if (value < 0) {
	fatalperror(pty, "select");
    }
    if (FD_ISSET(s, &excepts)) {
	return 1;
    } else {
	return 0;
    }
}

void 	ptyflush(void)
{
	int n;

	if ((n = pfrontp - pbackp) > 0) {
		DIAG((TD_REPORT | TD_PTYDATA),
		     netoprintf("td: ptyflush %d chars\r\n", n););
		DIAG(TD_PTYDATA, printdata("pd", pbackp, n));
		n = write(pty, pbackp, n);
	}
	if (n < 0) {
		if (errno == EWOULDBLOCK || errno == EINTR)
			return;
		cleanup(0);
	}
	pbackp += n;
	if (pbackp == pfrontp)
		pbackp = pfrontp = ptyobuf;
}

/*
 * nextitem()
 *
 *	Return the address of the next "item" in the TELNET data
 * stream.  This will be the address of the next character if
 * the current address is a user data character, or it will
 * be the address of the character following the TELNET command
 * if the current address is a TELNET IAC ("I Am a Command")
 * character.
 */
static
const char *
nextitem(
	const unsigned char *current, const unsigned char *end,
	const unsigned char *next, const unsigned char *nextend
) {
	if (*current++ != IAC) {
		while (current < end && *current++ != IAC)
			;
		goto out;
	}

	if (current >= end) {
		current = next;
		if (!current) {
			return 0;
		}
		end = nextend;
		next = 0;
	}

	switch (*current++) {
	case DO:
	case DONT:
	case WILL:
	case WONT:
		current++;
		break;
	case SB:		/* loop forever looking for the SE */
		for (;;) {
			int iac;

			while (iac = 0, current < end) {
				if (*current++ == IAC) {
					if (current >= end) {
						iac = 1;
						break;
					}
iac:
					if (*current++ == SE) {
						goto out;
					}
				}
			}

			current = next;
			if (!current) {
				return 0;
			}
			end = nextend;
			next = 0;
			if (iac) {
				goto iac;
			}
		}
	}

out:
	return (const char *) (next ? (next + (current - end)) : current );
}  /* end of nextitem */


/*
 * netclear()
 *
 *	We are about to do a TELNET SYNCH operation.  Clear
 * the path to the network.
 *
 *	Things are a bit tricky since we may have sent the first
 * byte or so of a previous TELNET command into the network.
 * So, we have to scan the network buffer from the beginning
 * until we are up to where we want to be.
 *
 *	A side effect of what we do, just to keep things
 * simple, is to clear the urgent data pointer.  The principal
 * caller should be setting the urgent data pointer AFTER calling
 * us in any case.
 */
void netclear(void)
{
	doclear++;
	netflush();
	doclear--;
}  /* end of netclear */

#ifdef USE_SSL
static int
SSL_writev(SSL *ssl_con,const struct iovec *vector,int num)
{
	const struct iovec *v = vector;

	int ret;
	int len = 0;

	while (num > 0) {
		ret = SSL_write(ssl_con, v->iov_base, v->iov_len);
		if (ret < 0)
			return ret;
		if (ret != v->iov_len)
			syslog(LOG_NOTICE, "SSL_writev: short write\n");
		num -= v->iov_len;
		len += ret;
		v++;
	}
	return len;
}
#endif /* USE_SSL */

static void
netwritebuf(void)
{
	struct iovec *vector;
	struct iovec *v;
	struct buflist *lp;
	ssize_t n;
	size_t len;
	int ltrailing = trailing;

	if (!listlen)
		return;

	vector = malloc(listlen * sizeof(struct iovec));
	if (!vector) {
		return;
	}

	len = listlen - (doclear & ltrailing);
	v = vector;
	lp = head.next;
	while (lp != &head) {
		if (lp == urg) {
			len = v - vector;
			if (!len) {
#ifdef USE_SSL
			        if (ssl_active_flag)
				  n = SSL_write(ssl_con, lp->buf, 1);	
				else
#endif /* USE_SSL */
				n = send(net, lp->buf, 1, MSG_OOB);
				if (n > 0) {
					urg = 0;
				}
				goto epi;
			}
			break;
		}
		v->iov_base = lp->buf;
		v->iov_len = lp->len;
		v++;
		lp = lp->next;
	}

	vector->iov_base = (char *)vector->iov_base + skip;
	vector->iov_len -= skip;

	if(vector->iov_len == 0 ) {
	  n=0;
	} else {

#ifdef USE_SSL
	  if (ssl_active_flag)
		n = SSL_writev(ssl_con, vector, len);	/* normal write */
	  else	
#endif /* USE_SSL */
		n = writev(net, vector, len);

epi:
	  free(vector);

	  if (n < 0) {
		if (errno != EWOULDBLOCK && errno != EINTR)
		  cleanup(0);
		return;
	  }
	}

	len = n + skip;

	lp = head.next;
	while (lp->len <= len) {
		if (lp == tail && ltrailing) {
			break;
		}

		len -= lp->len;

		head.next = lp->next;
		listlen--;
		free(lp->buf);
		free(lp);

		lp = head.next;
		if (lp == &head) {
			tail = &head;
			break;
		}
	}

	if(ltrailing && (len==0)) {
		ltrailing=trailing=0;
	}

	skip = len;
}

/*
 *  netflush
 *             Send as much data as possible to the network,
 *     handling requests for urgent data.
 */
int
netflush(void)
{
	if (fflush(netfile)) {
		/* out of memory? */
		cleanup(0);
		return 0;
	}
	netwritebuf();
	return 1;
}

int
writenet(char *b , int l)
{
  return(fwrite(b, 1, l, netfile));
}


/*
 * miscellaneous functions doing a variety of little jobs follow ...
 */


void
fatal(int f, const char *msg)
{
	char buf[BUFSIZ];

	(void) snprintf(buf, sizeof(buf), "telnetd: %s.\r\n", msg);
#if	defined(ENCRYPT)
	if (encrypt_output) {
		/*
		 * Better turn off encryption first....
		 * Hope it flushes...
		 */
		encrypt_send_end();
		netflush();
	}
#endif
	(void) write(f, buf, (int)strlen(buf));
#ifdef USE_SSL
        if (debug) {
	    fprintf(stderr,"fatal called: %s\r\n",msg);
	    fflush(stderr);
	}
#endif /* USE_SSL */
	sleep(1);	/*XXX*/
	exit(1);
}

void
fatalperror(int f, const char *msg)
{
	char buf[BUFSIZ];
	snprintf(buf, sizeof(buf), "%s: %s\r\n", msg, strerror(errno));
	fatal(f, buf);
}

char *editedhost;
struct utsname kerninfo;

void
edithost(const char *pat, const char *host)
{
	char *res;

	uname(&kerninfo);

	if (!pat)
		pat = "";

	res = realloc(editedhost, strlen(pat) + strlen(host) + 1);
	if (!res) {
		if (editedhost) {
			free(editedhost);
			editedhost = 0;
		}
		fprintf(stderr, "edithost: Out of memory\n");
		return;
	}
	editedhost = res;

	while (*pat) {
		switch (*pat) {

		case '#':
			if (*host)
				host++;
			break;

		case '@':
			if (*host)
				*res++ = *host++;
			break;

		default:
			*res++ = *pat;
			break;
		}
		pat++;
	}
	if (*host)
		(void) strcpy(res, host);
	else
		*res = '\0';
}

static char *putlocation;

static 
void
putstr(const char *s)
{
    while (*s) putchr(*s++);
}

void putchr(int cc)
{
	*putlocation++ = cc;
}

static char fmtstr[] = { "%H:%M on %A, %d %B %Y" };

void putf(const char *cp, char *where)
{
	char *slash;
	time_t t;
	char db[100];

	if (where)
	putlocation = where;

	while (*cp) {
		if (*cp != '%') {
			putchr(*cp++);
			continue;
		}
		switch (*++cp) {

		case 't':
			slash = strrchr(line, '/');
			if (slash == NULL)
				putstr(line);
			else
				putstr(slash+1);
			break;

#ifdef USE_SSL
                case 'V':
			/* output prog ver and SSLeay ver */
		        putstr("[SSL 0.10-");
			putstr(SSLeay_version(SSLEAY_VERSION));
			putstr("] ");
		        break;
#else /* !USE_SSL */

		/* ignore the version token ... so we can have 
		 * just the one version string which we hack
		 * here rather than all over the place
		 */
                case 'V':
		        break;
#endif /* USE_SSL */

		case 'h':
			if (editedhost) {
				putstr(editedhost);
			}
			break;

		case 'd':
			(void)time(&t);
			(void)strftime(db, sizeof(db), fmtstr, localtime(&t));
			putstr(db);
			break;

		case '%':
			putchr('%');
			break;

		case 'D':
			{
				char	buff[128];

				if (getdomainname(buff,sizeof(buff)) < 0
					|| buff[0] == '\0'
					|| strcmp(buff, "(none)") == 0)
					break;
				putstr(buff);
			}
			break;

		case 'i':
			{
				char buff[3];
				FILE *fp;
				int p, c;

				if ((fp = fopen(ISSUE_FILE, "r")) == NULL)
					break;
				p = '\n';
				while ((c = fgetc(fp)) != EOF) {
					if (p == '\n' && c == '#') {
						do {
							c = fgetc(fp);
						} while (c != EOF && c != '\n');
						continue;
					} else if (c == '%') {
						buff[0] = c;
						c = fgetc(fp);
						if (c == EOF) break;
						buff[1] = c;
						buff[2] = '\0';
						putf(buff, NULL);
					} else {
						if (c == '\n') putchr('\r');
						putchr(c);
						p = c;
					}
				};
				(void) fclose(fp);
			}
			return; /* ignore remainder of the banner string */
			/*NOTREACHED*/

		case 's':
			putstr(kerninfo.sysname);
			break;

		case 'm':
			putstr(kerninfo.machine);
			break;

		case 'r':
			putstr(kerninfo.release);
			break;

		case 'v':
#ifdef __linux__
			putstr(kerninfo.version);
#else
			puts(kerninfo.version);
#endif
			break;
		}
		cp++;
	}
}

#ifdef DIAGNOSTICS
/*
 * Print telnet options and commands in plain text, if possible.
 */
void
printoption(const char *fmt, int option)
{
	if (TELOPT_OK(option))
		netoprintf("%s %s\r\n", fmt, TELOPT(option));
	else if (TELCMD_OK(option))
		netoprintf("%s %s\r\n", fmt, TELCMD(option));
	else
		netoprintf("%s %d\r\n", fmt, option);
}

/* direction: '<' or '>' */
/* pointer: where suboption data sits */
/* length: length of suboption data */
void
printsub(char direction, unsigned char *pointer, int length)
{
    register int i = -1;
#ifdef AUTHENTICATE
    char buf[512];
#endif

        if (!(diagnostic & TD_OPTIONS))
		return;

	if (direction) {
	    netoprintf("td: %s suboption ",
		       direction == '<' ? "recv" : "send");
	    if (length >= 3) {
		register int j;

		i = pointer[length-2];
		j = pointer[length-1];

		if (i != IAC || j != SE) {
		    netoprintf("(terminated by ");
		    if (TELOPT_OK(i))
			netoprintf("%s ", TELOPT(i));
		    else if (TELCMD_OK(i))
			netoprintf("%s ", TELCMD(i));
		    else
			netoprintf("%d ", i);
		    if (TELOPT_OK(j))
			netoprintf("%s", TELOPT(j));
		    else if (TELCMD_OK(j))
			netoprintf("%s", TELCMD(j));
		    else
			netoprintf("%d", j);
		    netoprintf(", not IAC SE!) ");
		}
	    }
	    length -= 2;
	}
	if (length < 1) {
	    netoprintf("(Empty suboption???)");
	    return;
	}
	switch (pointer[0]) {
	case TELOPT_TTYPE:
	    netoprintf("TERMINAL-TYPE ");
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netoprintf("IS \"%.*s\"", length-2, (char *)pointer+2);
		break;
	    case TELQUAL_SEND:
		netoprintf("SEND");
		break;
	    default:
		netoprintf("- unknown qualifier %d (0x%x).",
				pointer[1], pointer[1]);
	    }
	    break;
	case TELOPT_TSPEED:
	    netoprintf("TERMINAL-SPEED");
	    if (length < 2) {
		netoprintf(" (empty suboption???)");
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netoprintf(" IS %.*s", length-2, (char *)pointer+2);
		break;
	    default:
		if (pointer[1] == 1)
		    netoprintf(" SEND");
		else
		    netoprintf(" %d (unknown)", pointer[1]);
		for (i = 2; i < length; i++) {
		    netoprintf(" ?%d?", pointer[i]);
		}
		break;
	    }
	    break;

	case TELOPT_LFLOW:
	    netoprintf("TOGGLE-FLOW-CONTROL");
	    if (length < 2) {
		netoprintf(" (empty suboption???)");
		break;
	    }
	    switch (pointer[1]) {
	    case LFLOW_OFF:
		netoprintf(" OFF"); break;
	    case LFLOW_ON:
		netoprintf(" ON"); break;
	    case LFLOW_RESTART_ANY:
		netoprintf(" RESTART-ANY"); break;
	    case LFLOW_RESTART_XON:
		netoprintf(" RESTART-XON"); break;
	    default:
		netoprintf(" %d (unknown)", pointer[1]);
	    }
	    for (i = 2; i < length; i++) {
		netoprintf(" ?%d?", pointer[i]);
	    }
	    break;

	case TELOPT_NAWS:
	    netoprintf("NAWS");
	    if (length < 2) {
		netoprintf(" (empty suboption???)");
		break;
	    }
	    if (length == 2) {
		netoprintf(" ?%d?", pointer[1]);
		break;
	    }
	    netoprintf(" %d %d (%d)",
		pointer[1], pointer[2],
		(int)((((unsigned int)pointer[1])<<8)|((unsigned int)pointer[2])));
	    if (length == 4) {
		netoprintf(" ?%d?", pointer[3]);
		break;
	    }
	    netoprintf(" %d %d (%d)",
		pointer[3], pointer[4],
		(int)((((unsigned int)pointer[3])<<8)|((unsigned int)pointer[4])));
	    for (i = 5; i < length; i++) {
		netoprintf(" ?%d?", pointer[i]);
	    }
	    break;

	case TELOPT_LINEMODE:
	    netoprintf("LINEMODE ");
	    if (length < 2) {
		netoprintf(" (empty suboption???)");
		break;
	    }
	    switch (pointer[1]) {
	    case WILL:
		netoprintf("WILL ");
		goto common;
	    case WONT:
		netoprintf("WONT ");
		goto common;
	    case DO:
		netoprintf("DO ");
		goto common;
	    case DONT:
		netoprintf("DONT ");
	    common:
		if (length < 3) {
		    netoprintf("(no option???)");
		    break;
		}
		switch (pointer[2]) {
		case LM_FORWARDMASK:
		    netoprintf("Forward Mask");
		    for (i = 3; i < length; i++) {
			netoprintf(" %x", pointer[i]);
		    }
		    break;
		default:
		    netoprintf("%d (unknown)", pointer[2]);
		    for (i = 3; i < length; i++) {
			netoprintf(" %d", pointer[i]);
		    }
		    break;
		}
		break;
		
	    case LM_SLC:
		netoprintf("SLC");
		for (i = 2; i < length - 2; i += 3) {
		    if (SLC_NAME_OK(pointer[i+SLC_FUNC]))
			netoprintf(" %s", SLC_NAME(pointer[i+SLC_FUNC]));
		    else
			netoprintf(" %d", pointer[i+SLC_FUNC]);
		    switch (pointer[i+SLC_FLAGS]&SLC_LEVELBITS) {
		    case SLC_NOSUPPORT:
			netoprintf(" NOSUPPORT"); break;
		    case SLC_CANTCHANGE:
			netoprintf(" CANTCHANGE"); break;
		    case SLC_VARIABLE:
			netoprintf(" VARIABLE"); break;
		    case SLC_DEFAULT:
			netoprintf(" DEFAULT"); break;
		    }
		    netoprintf("%s%s%s",
			pointer[i+SLC_FLAGS]&SLC_ACK ? "|ACK" : "",
			pointer[i+SLC_FLAGS]&SLC_FLUSHIN ? "|FLUSHIN" : "",
			pointer[i+SLC_FLAGS]&SLC_FLUSHOUT ? "|FLUSHOUT" : "");
		    if (pointer[i+SLC_FLAGS]& ~(SLC_ACK|SLC_FLUSHIN|
						SLC_FLUSHOUT| SLC_LEVELBITS)) {
			netoprintf("(0x%x)", pointer[i+SLC_FLAGS]);
		    }
		    netoprintf(" %d;", pointer[i+SLC_VALUE]);
		    if ((pointer[i+SLC_VALUE] == IAC) &&
			(pointer[i+SLC_VALUE+1] == IAC))
				i++;
		}
		for (; i < length; i++) {
		    netoprintf(" ?%d?", pointer[i]);
		}
		break;

	    case LM_MODE:
		netoprintf("MODE ");
		if (length < 3) {
		    netoprintf("(no mode???)");
		    break;
		}
		{
		    char tbuf[32];
		    snprintf(tbuf, sizeof(tbuf), "%s%s%s%s%s",
			pointer[2]&MODE_EDIT ? "|EDIT" : "",
			pointer[2]&MODE_TRAPSIG ? "|TRAPSIG" : "",
			pointer[2]&MODE_SOFT_TAB ? "|SOFT_TAB" : "",
			pointer[2]&MODE_LIT_ECHO ? "|LIT_ECHO" : "",
			pointer[2]&MODE_ACK ? "|ACK" : "");
		    netoprintf("%s", tbuf[1] ? &tbuf[1] : "0");
		}
		if (pointer[2]&~(MODE_EDIT|MODE_TRAPSIG|MODE_ACK)) {
		    netoprintf(" (0x%x)", pointer[2]);
		}
		for (i = 3; i < length; i++) {
		    netoprintf(" ?0x%x?", pointer[i]);
		}
		break;
	    default:
		netoprintf("%d (unknown)", pointer[1]);
		for (i = 2; i < length; i++) {
		    netoprintf(" %d", pointer[i]);
		}
	    }
	    break;

	case TELOPT_STATUS: {
	    const char *cp;
	    register int j, k;

	    netoprintf("STATUS");

	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netoprintf(" IS\r\n");

		for (i = 2; i < length; i++) {
		    switch(pointer[i]) {
		    case DO:	cp = "DO"; goto common2;
		    case DONT:	cp = "DONT"; goto common2;
		    case WILL:	cp = "WILL"; goto common2;
		    case WONT:	cp = "WONT"; goto common2;
		    common2:
			i++;
			if (TELOPT_OK((int)pointer[i]))
			    netoprintf(" %s %s", cp, TELOPT(pointer[i]));
			else
			    netoprintf(" %s %d", cp, pointer[i]);

			netoprintf("\r\n");
			break;

		    case SB:
			netoprintf(" SB ");
			i++;
			j = k = i;
			while (j < length) {
			    if (pointer[j] == SE) {
				if (j+1 == length)
				    break;
				if (pointer[j+1] == SE)
				    j++;
				else
				    break;
			    }
			    pointer[k++] = pointer[j++];
			}
			printsub(0, &pointer[i], k - i);
			if (i < length) {
			    netoprintf(" SE");
			    i = j;
			} else
			    i = j - 1;

			netoprintf("\r\n");

			break;
				
		    default:
			netoprintf(" %d", pointer[i]);
			break;
		    }
		}
		break;
	    default:
		if (pointer[1] == TELQUAL_SEND)
		    netoprintf(" SEND");
		else
		    netoprintf(" %d (unknown)", pointer[1]);
		for (i = 2; i < length; i++) {
		    netoprintf(" ?%d?", pointer[i]);
		}
		break;
	    }
	    break;
	  }

	case TELOPT_XDISPLOC:
	    netoprintf("X-DISPLAY-LOCATION ");
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netoprintf("IS \"%.*s\"", length-2, (char *)pointer+2);
		break;
	    case TELQUAL_SEND:
		netoprintf("SEND");
		break;
	    default:
		netoprintf("- unknown qualifier %d (0x%x).",
				pointer[1], pointer[1]);
	    }
	    break;

	case TELOPT_ENVIRON:
	    netoprintf("ENVIRON ");
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netoprintf("IS ");
		goto env_common;
	    case TELQUAL_SEND:
		netoprintf("SEND ");
		goto env_common;
	    case TELQUAL_INFO:
		netoprintf("INFO ");
	    env_common:
		{
		    register int noquote = 2;
		    for (i = 2; i < length; i++ ) {
			switch (pointer[i]) {
			case ENV_USERVAR:
			case ENV_VAR:
			    if (pointer[1] == TELQUAL_SEND)
				goto def_case;
			    if (pointer[i] == ENV_VAR)
				netoprintf("%s", "\" VAR " + noquote);
			    else
				netoprintf("%s", "\" USERVAR " + noquote);
			    noquote = 2;
			    break;

			case ENV_VALUE:
			    netoprintf("%s", "\" VALUE " + noquote);
			    noquote = 2;
			    break;

			case ENV_ESC:
			    netoprintf("%s", "\" ESC " + noquote);
			    noquote = 2;
			    break;

			default:
			def_case:
			    if (isprint(pointer[i]) && pointer[i] != '"') {
				if (noquote) {
				    netoprintf("\"");
				    noquote = 0;
				}
				netoprintf("%c", pointer[i]);
			    } else {
				netoprintf("\" %03o " + noquote,
							pointer[i]);
				noquote = 2;
			    }
			    break;
			}
		    }
		    if (!noquote)
			netoprintf("\"");
		    break;
		}
	    }
	    break;

#if	defined(AUTHENTICATE)
	case TELOPT_AUTHENTICATION:
	    netoprintf("AUTHENTICATION");
	
	    if (length < 2) {
		netoprintf(" (empty suboption???)");
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_REPLY:
	    case TELQUAL_IS:
		netoprintf(" %s ", (pointer[1] == TELQUAL_IS) ?
							"IS" : "REPLY");
		if (AUTHTYPE_NAME_OK(pointer[2]))
		    netoprintf("%s ", AUTHTYPE_NAME(pointer[2]));
		else
		    netoprintf("%d ", pointer[2]);
		if (length < 3) {
		    netoprintf("(partial suboption???)");
		    break;
		}
		netoprintf("%s|%s",
			((pointer[3] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT) ?
			"CLIENT" : "SERVER",
			((pointer[3] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) ?
			"MUTUAL" : "ONE-WAY");

		auth_printsub(&pointer[1], length - 1, (unsigned char *) buf, sizeof(buf));
		netoprintf("%s", buf);
		break;

	    case TELQUAL_SEND:
		i = 2;
		netoprintf(" SEND ");
		while (i < length) {
		    if (AUTHTYPE_NAME_OK(pointer[i]))
			netoprintf("%s ", AUTHTYPE_NAME(pointer[i]));
		    else
			netoprintf("%d ", pointer[i]);
		    if (++i >= length) {
			netoprintf("(partial suboption???)");
			break;
		    }
		    netoprintf("%s|%s ",
			((pointer[i] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT) ?
							"CLIENT" : "SERVER",
			((pointer[i] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) ?
							"MUTUAL" : "ONE-WAY");
		    ++i;
		}
		break;

	    case TELQUAL_NAME:
		i = 2;
		netoprintf(" NAME \"");
		/*
		 * Was:
		 *    while (i < length)
		 *       *nfrontp += pointer[i++];
		 *    *nfrontp += '"';
		 *
		 * but I'm pretty sure that's wrong...
		 */
		while (i < length)
		    netoprintf("%c", pointer[i++]);
		netoprintf("\"");
		break;

	    default:
		    for (i = 2; i < length; i++) {
			netoprintf(" ?%d?", pointer[i]);
		    }
		    break;
	    }
	    break;
#endif

#if	defined(ENCRYPT)
	case TELOPT_ENCRYPT:
	    netoprintf("ENCRYPT");
	    if (length < 2) {
		netoprintf(" (empty suboption???)");
		break;
	    }
	    switch (pointer[1]) {
	    case ENCRYPT_START:
		netoprintf(" START");
		break;

	    case ENCRYPT_END:
		netoprintf(" END");
		break;

	    case ENCRYPT_REQSTART:
		netoprintf(" REQUEST-START");
		break;

	    case ENCRYPT_REQEND:
		netoprintf(" REQUEST-END");
		break;

	    case ENCRYPT_IS:
	    case ENCRYPT_REPLY:
		netoprintf(" %s ", (pointer[1] == ENCRYPT_IS) ?
							"IS" : "REPLY");
		if (length < 3) {
		    netoprintf(" (partial suboption???)");
		    break;
		}
		if (ENCTYPE_NAME_OK(pointer[2]))
		    netoprintf("%s ", ENCTYPE_NAME(pointer[2]));
		else
		    netoprintf(" %d (unknown)", pointer[2]);

		encrypt_printsub(&pointer[1], length - 1, buf, sizeof(buf));
		netoprintf("%s", buf);
		break;

	    case ENCRYPT_SUPPORT:
		i = 2;
		netoprintf(" SUPPORT ");
		while (i < length) {
		    if (ENCTYPE_NAME_OK(pointer[i]))
			netoprintf("%s ", ENCTYPE_NAME(pointer[i]));
		    else
			netoprintf("%d ", pointer[i]);
		    i++;
		}
		break;

	    case ENCRYPT_ENC_KEYID:
		netoprintf(" ENC_KEYID", pointer[1]);
		goto encommon;

	    case ENCRYPT_DEC_KEYID:
		netoprintf(" DEC_KEYID", pointer[1]);
		goto encommon;

	    default:
		netoprintf(" %d (unknown)", pointer[1]);
	    encommon:
		for (i = 2; i < length; i++) {
		    netoprintf(" %d", pointer[i]);
		}
		break;
	    }
	    break;
#endif

	default:
	    if (TELOPT_OK(pointer[0]))
	        netoprintf("%s (unknown)", TELOPT(pointer[0]));
	    else
	        netoprintf("%d (unknown)", pointer[0]);
	    for (i = 1; i < length; i++) {
		netoprintf(" %d", pointer[i]);
	    }
	    break;
	}
	netoprintf("\r\n");
}

/*
 * Dump a data buffer in hex and ascii to the output data stream.
 */
void
printdata(const char *tag, const char *ptr, int cnt)
{
	register int i;
	char xbuf[30];

	while (cnt) {
		/* add a line of output */
		netoprintf("%s: ", tag);
		for (i = 0; i < 20 && cnt; i++) {
			netoprintf("%02x", *ptr);
			if (isprint(*ptr)) {
				xbuf[i] = *ptr;
			} else {
				xbuf[i] = '.';
			}
			if (i % 2) { 
				netoprintf(" ");
			}
			cnt--;
			ptr++;
		}
		xbuf[i] = '\0';
		netoprintf(" %s\r\n", xbuf );
	} 
}
#endif /* DIAGNOSTICS */

static struct buflist *
addbuf(const char *buf, size_t len)
{
	struct buflist *bufl;

	bufl = malloc(sizeof(struct buflist));
	if (!bufl) {
		return 0;
	}
	bufl->next = tail->next;
	bufl->buf = malloc(len);
	if (!bufl->buf) {
		free(bufl);
		return 0;
	}
	bufl->len = len;

	tail = tail->next = bufl;
	listlen++;

	memcpy(bufl->buf, buf, len);
	return bufl;
}

static ssize_t
netwrite(void *cookie, const char *buf, size_t len)
{
	size_t ret;
	const char *const end = buf + len;
	int ltrailing = trailing;
	int ldoclear = doclear;

#define	wewant(p)	((*p&0xff) == IAC) && \
				((*(p+1)&0xff) != EC) && ((*(p+1)&0xff) != EL)

	ret = 0;

	if (ltrailing) {
		const char *p;
		size_t l;
		size_t m = tail->len;

		if((tail->buf == NULL) || (tail->len==0))
		{
			p = nextitem((unsigned char *) buf, (unsigned char *) end,0,0);
		}
		else
		{
			p = nextitem((unsigned char *) tail->buf, (unsigned char *) (tail->buf + tail->len),
						 (unsigned char *) buf, (unsigned char *) end);
		}
		ltrailing = !p;
		if (ltrailing) {
			p = end;
		}

		l = p - buf;
		tail->len += l;
		tail->buf = realloc(tail->buf, tail->len);
		if (!tail->buf) {
			return -1;
		}

		memcpy(tail->buf + m, buf, l);
		buf += l;
		len -= l;
		ret += l;
		trailing = ltrailing;
	}

	if (ldoclear) {
		struct buflist *lpprev;

		skip = 0;
		lpprev = &head;
		for (;;) {
			struct buflist *lp;

			lp = lpprev->next;

			if (lp == &head) {
				tail = lpprev;
				break;
			}

			if (lp == tail && ltrailing) {
				break;
			}

			if (!wewant(lp->buf)) {
				lpprev->next = lp->next;
				listlen--;
				free(lp->buf);
				free(lp);
			} else {
				lpprev = lp;
			}
		}
	}

	while (len) {
		const char *p;
		size_t l;

		p = nextitem((unsigned char *) buf, (unsigned char *) end, 0, 0);
		ltrailing = !p;
		if (ltrailing) {
			p = end;
		} else if (ldoclear) {
			if (!wewant(buf)) {
				l = p - buf;
				goto cont;
			}
		}

		l = p - buf;
		if (!addbuf(buf, l)) {
			return ret ? ret : -1;
		}
		trailing = ltrailing;

cont:
		buf += l;
		len -= l;
		ret += l;
	}

	netwritebuf();
	return ret;
}

void
netopen() {
	static const cookie_io_functions_t funcs = {
		read: 0, write: netwrite, seek: 0, close: 0
	};

	netfile = fopencookie(0, "w", funcs);
}

extern int not42;
void
sendurg(const char *buf, size_t len) {
	if (!not42) {
		fwrite(buf, 1, len, netfile);
		return;
	}

	urg = addbuf(buf, len);
}

size_t
netbuflen(int flush) {
	if (flush) {
		netflush();
	}
	return listlen != 1 ? listlen : tail->len - skip;
}
