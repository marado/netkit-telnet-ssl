#ifdef	USE_SSL
/* 
 * The modifications to support SSLeay were done by Tim Hudson
 * tjh@mincom.oz.au
 *
 * You can do whatever you like with these patches except pretend that
 * you wrote them. 
 *
 * Email ssl-users-request@mincom.oz.au to get instructions on how to
 * join the mailing list that discusses SSLeay and also these patches.
 *
 */

/* ssl.c    - interface to Eric Young's SSLeay library (eay@mincom.oz.au)
 *
 * see LICENSE for details 
 *
 * xx-Aug-96 tjh    reworked the client certificate stuff into a form
 * ................ where it is useful with SSLeay-0.6.x which changed
 * ................ lots of things in the handling of the verify function
 * 01-Jul-95 tjh    merged patches from Steven Schoch 
 * ................ <schoch@sheba.arc.nasa.gov> that add in the certsok
 * ................ option for using signed certificates rather than 
 * ................ explicit passwords for authentication (modified a little
 * ................ to add in an option that controls this feature)
 * 26-Apr-95 tjh    original coding
 *
 * tjh@mincom.oz.au
 * tjh@mincom.com
 *
 * Tim Hudson
 * Mincom Pty Ltd
 * Australia
 * +61 7 3303 3333
 *
 */

#include <sys/types.h>
#include "arpa/telnet.h"
#include <stdio.h>
#ifdef	__STDC__
#include <stdlib.h>
#endif
#ifdef	NO_STRING_H
#include <strings.h>
#else
#include <string.h>
#endif

#include <syslog.h>
#include <unistd.h>
#include <openssl/err.h>

#include "auth.h"
#include "misc.h"

#include "crypto.h"

#if SSLEAY_VERSION_NUMBER >= 0x0800
#define SSLEAY8
#endif
 
#ifdef SSLEAY8
#define ONELINE_NAME(X) X509_NAME_oneline(X,NULL,0)
#else
#define ONELINE_NAME(X) X509_NAME_oneline(X)
#endif

#ifdef SSLEAY8
#include "bio.h"
#endif
#include "buffer.h"

#include "x509.h"
#include "ssl.h"

/* quick translation ... */
#ifndef VERIFY_ERR_UNABLE_TO_GET_ISSUER
#define VERIFY_ERR_UNABLE_TO_GET_ISSUER X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
#endif
#ifndef VERIFY_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
#define VERIFY_ERR_DEPTH_ZERO_SELF_SIGNED_CERT X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT 
#endif
#ifndef VERIFY_ERR_SELF_SIGNED_CERT_IN_CHAIN
# define VERIFY_ERR_SELF_SIGNED_CERT_IN_CHAIN X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
#endif
#ifndef VERIFY_OK
#define VERIFY_OK X509_V_OK
#endif
#ifndef VERIFY_ERR_UNABLE_TO_GET_ISSUER
#define VERIFY_ERR_UNABLE_TO_GET_ISSUER X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
#endif

/* need to think about this mapping in terms of what the real
 * equivalent of this actually is
 */
#ifndef VERIFY_ROOT_OK
#define VERIFY_ROOT_OK VERIFY_OK
#endif

/* Two possibilities:
 *   X509_V_ERR_INVALID_PURPOSE
 * or
 *   X509_V_ERR_APPLICATION_VERIFICATION
 *
 * The resulting error messages are not particularly helpful.
 */
#ifndef VERIFY_REJECTED_BY_CERTSOK
# define VERIFY_REJECTED_BY_CERTSOK X509_V_ERR_APPLICATION_VERIFICATION
#endif

#ifndef SSL_USERS_FILE
# define SSL_USERS_FILE "/etc/ssl.users"
#endif

extern int netflush(void);

extern int auth_debug_mode;
static int auth_ssl_valid = 0;
static char *auth_ssl_name = 0;    /* this holds the oneline name */

extern int ssl_only_flag;
extern int ssl_debug_flag;
extern int ssl_active_flag;
extern int ssl_secure_flag;
extern int ssl_verify_flag;
extern int ssl_certsok_flag;       /* if this is set then we enable the
                                    * /etc/ssl.users stuff for allowing
				    * access - just to make sure we don't
				    * switch it on unless we really want it
                                    */
extern int ssl_cert_required;      /* client certificate is mandatory! */

extern int ssl_verbose_flag;
extern int ssl_disabled_flag;

int server_verify_callback();
int client_verify_callback();

extern SSL *ssl_con;

#include "buffer.h"

BIO *bio_err=NULL;

int auth_failed=0;


/* compile this set to 1 to negotiate SSL but not actually start it */
static int ssl_dummy_flag=0;

static unsigned char str_data[1024] = { IAC, SB, TELOPT_AUTHENTICATION, 0,
			  		AUTHTYPE_SSL, };

#define AUTH_SSL_START     1
#define AUTH_SSL_ACCEPT    2
#define AUTH_SSL_REJECT    3


/* this is called by both the ssl.c auth connect and the mainline
 * telnet connect if we are talking straight ssl with no telnet
 * protocol --tjh
 */
void
display_connect_details(ssl_con,verbose)
SSL *ssl_con;
int verbose;
{
    X509 *peer;
    char *p;

    if (ssl_active_flag && verbose) {
#ifdef SSLEAY8
	int i;
#endif /* SSLEAY8 */
	fprintf(stderr,"[SSL cipher=");
#ifdef SSLEAY8
	/* grab the full list of ciphers */
	i=0;
	while((p=(char *)SSL_get_cipher_list(ssl_con,i++))!=NULL) {
	    if (i>1) {
		fprintf(stderr,":");
	    }
	    fprintf(stderr, "%s", p);
	}
	if(i==1) {
	    fprintf(stderr, "<NULL>");
	}
#else /* !SSLEAY8 */
	p=SSL_get_cipher(ssl_con);
	if(p) {
	    fprintf(stderr, "%s", p);
	} else {
	    /* the cipher list *can* be NULL ... useless but it happens! */
	    fprintf(stderr, "<NULL>");
	}
#endif /* !SSLEAY8 */
	fprintf(stderr,"]\r\n");
	peer=SSL_get_peer_certificate(ssl_con);
	if (peer != NULL) {
	    char *str;

	    str=ONELINE_NAME(X509_get_subject_name(peer));
	    fprintf(stderr,"[SSL subject=%s]\r\n",str);
	    free(str);
	    str=ONELINE_NAME(X509_get_issuer_name(peer));
	    fprintf(stderr,"[SSL issuer=%s]\r\n",str);
	    free(str);
	    X509_free(peer);
			    
	}
	fflush(stderr);
    }
}


	void
fprintd(fp, data, cnt)
	FILE *fp;
	unsigned char *data;
	int cnt;
{
	if (cnt > 16)
		cnt = 16;
	while (cnt-- > 0) {
		fprintf(fp," %02x", *data);
		++data;
	}
}

/* support routine to send out authentication message */
static int Data(ap, type, d, c)
Authenticator *ap;
int type;
void *d;
int c;
{
        unsigned char *p = str_data + 4;
	unsigned char *cd = (unsigned char *)d;

	if (c == -1)
		c = strlen((char *)cd);

        if (auth_debug_mode) {
                fprintf(stderr,"%s:%d: [%d] (%d)",
                        str_data[3] == TELQUAL_IS ? ">>>IS" : ">>>REPLY",
                        str_data[3],
                        type, c);
                fprintd(stderr,d, c);
                fprintf(stderr,"\r\n");
        }
	*p++ = ap->type;
	*p++ = ap->way;
	*p++ = type;
        while (c-- > 0) {
                if ((*p++ = *cd++) == IAC)
                        *p++ = IAC;
        }
        *p++ = IAC;
        *p++ = SE;
	if (str_data[3] == TELQUAL_IS)
		printsub('>', &str_data[2], p - (&str_data[2]));
        return(writenet((char *) str_data, p - str_data));
}

int auth_ssl_init(ap, server)
Authenticator *ap;
int server;
{
	/* ssl only option skips all of this muck ... */
	if (ssl_only_flag || ssl_disabled_flag) {
	    return 0;
	}

	SSL_load_error_strings();

	/* SSLeay-0.6 introduces the BIO stuff ... which we need for
	 * all the error reporting things! 
	 */
	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);

	if (server)
		str_data[3] = TELQUAL_REPLY;
	else
		str_data[3] = TELQUAL_IS;
	return(1);
}

/* client received a go-ahead for ssl */
int auth_ssl_send(ap)
Authenticator *ap;
{
	fprintf(stderr,"[SSL - attempting to switch on SSL]\r\n");
	fflush(stderr);

	if (!Data(ap, AUTH_SSL_START, NULL, 0 )) {
		if (auth_debug_mode)
			fprintf(stderr,"Not enough room for start data\r\n");
		return(0);
	}

	return(1);
}

/* server received an IS -- could (only) be SSL START */
void auth_ssl_is(ap, data, cnt)
Authenticator *ap;
unsigned char *data;
int cnt;
{
  /*	int valid; */

	if (cnt-- < 1)
		return;
	switch (*data++) {

	case AUTH_SSL_START:
		Data(ap, AUTH_SSL_ACCEPT, (void *)0, 0);
		netflush();

		auth_ssl_valid = 1;
		auth_finished(ap, AUTH_VALID);

		/* server starts the SSL stuff now ... */
		if (ssl_dummy_flag)
		    return;

		if (ssl_debug_flag && bio_err) {
		    (void) BIO_printf(bio_err, "AUTH SSL is starting\r\n");
		    (void) BIO_flush(bio_err);
		}

		if (!ssl_only_flag) {
		    /* only want/need verify if doing certsok stuff */
		    if (ssl_certsok_flag||ssl_cert_required) 
			SSL_set_verify(ssl_con,ssl_verify_flag,server_verify_callback);
		    if (SSL_accept(ssl_con) <= 0) {
			char *res, *p;
			/*
			syslog(LOG_WARNING, "ssl_accept error");
			*/

			res = ERR_error_string(ERR_peek_last_error(), NULL);
			p = strrchr(res, ':');

			syslog(LOG_NOTICE, "SSL_accept error: %s",
				p ? &p[1] : res);

			if (ssl_debug_flag && bio_err) {
			    (void) BIO_printf(bio_err, "SSL_accept: %s\r\n",
					      p ? &p[1] : res);
			    (void) BIO_flush(bio_err);
			}
			sleep(5);
			SSL_free(ssl_con);

			auth_finished(ap, AUTH_REJECT);

			_exit(1);
		    } else {
			ssl_active_flag=1;
		    }

		    /* now check to see that we got exactly what we 
		     * wanted from the caller ... if a certificate is
		     * required then we make 100% sure that we were
		     * given on during the handshake (as it is an optional
		     * part of SSL)
		     */
		    if ( ssl_cert_required ) {
		    	if (SSL_get_peer_certificate(ssl_con)==NULL) {

			    if (ssl_debug_flag) {
				fprintf(stderr,"[SSL - peer check failed]\r\n");
				fflush(stderr);
			    }
			    if (ssl_debug_flag && bio_err) {
				(void) BIO_printf(bio_err, "SSL - peer sent no certificate\r\n");
				(void) BIO_flush(bio_err);
			    }

			    /* LOGGING REQUIRED HERE! */
			    SSL_free(ssl_con);
			    auth_finished(ap, AUTH_REJECT);
			    _exit(1);
			}
		    }
		}
		break;

	default:
		fprintf(stderr,"[SSL - failed to switch on SSL]\r\n");
		fflush(stderr);

		if (auth_debug_mode) {
			fprintf(stderr,"Unknown SSL option %d\r\n", data[-1]);
			fprintf(stderr,"[SSL - negotiation failed]\r\n");
		}
		Data(ap, AUTH_SSL_REJECT, (void *)0, 0);

		auth_ssl_valid = 0;
		auth_finished(ap, AUTH_REJECT);
		break;
	}
}

/* client received REPLY -- could be SSL ACCEPT or REJECT */
void auth_ssl_reply(ap, data, cnt)
Authenticator *ap;
unsigned char *data;
int cnt;
{
  /*	int i; */
	int status;

	if (cnt-- < 1)
		return;
	switch (*data++) {

	case AUTH_SSL_ACCEPT:
		if (auth_debug_mode)
			fprintf(stderr,"SSL ACCEPT\r\n");
		fprintf(stderr,"[SSL - handshake starting]\r\n");

		auth_finished(ap, AUTH_VALID);

		if (ssl_dummy_flag) {
		    fprintf(stderr,"[SSL - Dummy Connected]\r\n");
		    fflush(stderr);
		    return;
		}

		/* right ... now we drop into the SSL library */
		if (!ssl_only_flag) {
		    SSL_set_verify(ssl_con,ssl_verify_flag,
		    				client_verify_callback);
		    if ((status = SSL_connect(ssl_con)) <= 0) {
			char *res, *p;

			auth_finished(0,AUTH_REJECT);

			res = ERR_error_string(ERR_peek_last_error(), NULL);
			p = strrchr(res, ':');
			fprintf(stderr,"SSL: %s\n", p ? &p[1] : res);
			fprintf(stderr,"telnet: Unable to ssl_connect to remote host\n");
			fflush(stderr);
			auth_failed=1;
			return;
		    } else {

			fprintf(stderr,"[SSL - OK]\r\n");
			fflush(stderr);

			ssl_active_flag=1;
			display_connect_details(ssl_con,ssl_debug_flag);
		    }
		}

		/* this is handy/required? */
		/*
		netflush();
		*/

		break;

	case AUTH_SSL_REJECT:
		if (auth_debug_mode)
			fprintf(stderr,"SSL REJECT\r\n");
		fprintf(stderr,"[SSL - failed to switch on SSL]\r\n");
		fprintf(stderr,"Trying plaintext login:\r\n");
		fflush(stderr);
		auth_finished(0,AUTH_REJECT);
		break;

	default:
		if (auth_debug_mode)
			fprintf(stderr,"Unknown SSL option %d\r\n", data[-1]);
		return;
	}
}

int auth_ssl_status(ap, name, level)
Authenticator *ap;
char *name;
int level;
{
	FILE *user_fp;
	char buf[2048];

	if (level < AUTH_USER)
		return(level);

	/*
	 * Look our name up in /etc/ssl.users.
	 * The format of this file is lines of this form:
	 *   user1,user2:/C=US/.....
	 * where user1 and user2 are usernames
	 */
	if (ssl_certsok_flag) {
	    user_fp = fopen(SSL_USERS_FILE, "r");
	    if (!auth_ssl_name || !user_fp || !UserNameRequested) {
	        /* If we haven't received a certificate, then don't 
		 * return AUTH_VALID. 
		 */
		if (UserNameRequested)
			strcpy(name, UserNameRequested);
		/* be tidy ... */
		if (user_fp)
		    fclose(user_fp);
		return AUTH_USER;
	    }
	    while (fgets(buf, sizeof buf, user_fp)) {
		char *cp;
		char *n;

		/* allow for comments in the file ... always nice
		 * to be able to add a little novel in files and
		 * also disable entries easily --tjh
		 */
		if (buf[0]=='#')
		    continue;

		if ((cp = strchr(buf, '\n')))
		    *cp = '\0';
		cp = strchr(buf, ':');
		if (!cp)
		    continue;
		*cp++ = '\0';
		if (strcasecmp(cp, auth_ssl_name) == 0) {
		    n = buf;
		    while (n) {
			cp = strchr(n, ',');
			if (cp)
			    *cp++ = '\0';
			if (UserNameRequested &&
			            !strcmp(UserNameRequested, n)) {
			    strcpy(name, n);
			    fclose(user_fp);

			    syslog(LOG_AUTH | LOG_INFO,
				   "Certsok autologin %s: %s",
				   UserNameRequested, auth_ssl_name);
			    if (ssl_debug_flag)
				(void) BIO_printf(bio_err,
						  "Certsok for %s: %s\r\n",
						  UserNameRequested,
						  auth_ssl_name);
			    return(AUTH_VALID);
			}
			n = cp;
		    }
		}
	    }
	    fclose(user_fp);
	    return(AUTH_USER);
	} else {
	    return(AUTH_USER);
	}
}

#define	BUMP(buf, len)		while (*(buf)) {++(buf), --(len);}
#define	ADDC(buf, len, c)	if ((len) > 0) {*(buf)++ = (c); --(len);}

void auth_ssl_printsub(data, cnt, buf, buflen)
unsigned char *data, *buf;
int cnt, buflen;
{
	char lbuf[32];
	register int i;

	buf[buflen-1] = '\0';		/* make sure its NULL terminated */
	buflen -= 1;

	switch(data[3]) {

	case AUTH_SSL_START:
		strncpy((char *)buf, " START ", buflen);
		goto common;

	case AUTH_SSL_REJECT:		/* Rejected (reason might follow) */
		strncpy((char *)buf, " REJECT ", buflen);
		goto common;

	case AUTH_SSL_ACCEPT:		/* Accepted (name might follow) */
		strncpy((char *)buf, " ACCEPT ", buflen);

	common:
		BUMP(buf, buflen);
		if (cnt <= 4)
			break;
		ADDC(buf, buflen, '"');
		for (i = 4; i < cnt; i++)
			ADDC(buf, buflen, data[i]);
		ADDC(buf, buflen, '"');
		ADDC(buf, buflen, '\0');
		break;

	default:
		sprintf(lbuf, " %d (unknown)", data[3]);
		strncpy((char *)buf, lbuf, buflen);
/*	common2: */
		BUMP(buf, buflen);
		for (i = 4; i < cnt; i++) {
			sprintf(lbuf, " %d", data[i]);
			strncpy((char *)buf, lbuf, buflen);
			BUMP(buf, buflen);
		}
		break;
	}
}


int
#ifdef SSLEAY8
server_verify_callback(ok, ctx)
int ok;
X509_STORE_CTX *ctx;
#else /* !SSLEAY8 */
server_verify_callback(ok, xs, xi, depth, error)
int ok;
char *xs, *xi;
int depth, error;
#endif /* SSLEAY8 */
{
    static char *saved_subject=NULL;
    /*    X509 *peer; */
    char *subject, *issuer;
#ifdef SSLEAY8
    int depth,error;
    X509 *xs;

    depth = X509_STORE_CTX_get_error_depth(ctx);
    error = X509_STORE_CTX_get_error(ctx);
    xs = X509_STORE_CTX_get_current_cert(ctx);

#endif /* SSLEAY8 */

#ifdef EXTRA_DEBUGGING
    if (ssl_debug_flag) {
	(void) BIO_printf(bio_err,"ssl:server_verify_callback:depth=%d ok=%d err=%d - %s\n",
	    depth,ok,error,X509_verify_cert_error_string(error));
	(void) BIO_flush(bio_err);
    }
#endif /* EXTRA_DEBUGGING */

    subject=issuer=NULL;

    /* first thing is to have a meaningful name for the current
     * certificate that is being verified ... and if we cannot
     * determine that then something is seriously wrong!
     */
    subject=(char *)ONELINE_NAME(X509_get_subject_name((X509 *)xs));
    if (subject==NULL) {
	if (ssl_debug_flag) 
	    ERR_print_errors(bio_err);
	ok=0;
	goto return_time;
    }
    issuer=(char *)ONELINE_NAME(X509_get_issuer_name((X509 *)xs));
    if (issuer==NULL) {
	if (ssl_debug_flag)
	    ERR_print_errors(bio_err);
	ok=0;
	goto return_time;
    }

    /* save the name of the first level subject as this is
     * the name we want to use to match for a username in
     * /etc/ssl.users later ... but *only* if we pass the
     * full verification of the certificate chain
     */
    if (depth==0) {
	/* clear things */
	if (saved_subject!=NULL) {
	    free(saved_subject);
	    saved_subject=NULL;
	}
	if (auth_ssl_name!=NULL) {
	    free(auth_ssl_name);
	    auth_ssl_name=NULL;
	}

	/* save the name if at least the first level is okay */
	if (ok)
	    saved_subject=strdup(subject);
    }

    /* if the client is using a self signed certificate then 
     * we need to decide if that is good enough for us to 
     * accept ... it certainly isn't good enough for anything
     * that wants to use the certificate as it is basically
     * junk of no value in this context!
     */
    if (error == VERIFY_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
	|| error == VERIFY_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
	if (ssl_cert_required) {
	    /* make 100% sure that in secure mode we drop the 
	     * connection if the server does not have a 
	     * real certificate!
	     */
	    if (ssl_debug_flag) {
		(void) BIO_printf(bio_err,"SSL: rejecting connection - self-signed cert\n");
		(void) BIO_flush(bio_err);
	    }

	    ok=0;
	    goto return_time;
	} else {
	    ok=1;
	    goto return_time;
	}
    }

    /* if we have any form of error in secure mode we reject the connection */
    if (! ((error==VERIFY_OK)||(error==VERIFY_ROOT_OK)) ) {
	if (ssl_cert_required) {
	    if (ssl_debug_flag) {
		(void) BIO_printf(bio_err,"SSL: rejecting connection - ");
		if (error==VERIFY_ERR_UNABLE_TO_GET_ISSUER) {
		    (void) BIO_printf(bio_err,"unknown issuer: %s\n",issuer);
		} else {
		    ERR_print_errors(bio_err);
		}
		(void) BIO_flush(bio_err);
	    }
	    ok=0;
	    goto return_time;
	} else {
	    /* be nice and display a lot more meaningful stuff 
	     * so that we know which issuer is unknown no matter
	     * what the callers options are ...
	     */
	    if (error==VERIFY_ERR_UNABLE_TO_GET_ISSUER) {
		if (ssl_debug_flag) {
		    (void) BIO_printf(bio_err,"SSL: unknown issuer: %s\n",issuer);
		    (void) BIO_flush(bio_err);
		}
	    }
	}
    } else {
	/* if we got all the way to the top of the tree then
	 * we *can* use this certificate for a username to 
	 * match ... in all other cases we must not!
	 */
	if ( (error==VERIFY_ROOT_OK) ) {
	    auth_ssl_name = saved_subject;
	    saved_subject = NULL;
	}
    }

return_time: ;

    /* clean up things */
    if (subject!=NULL)
	free(subject);
    if (issuer!=NULL)
	free(issuer);

    return ok;
}

int
#ifdef SSLEAY8
client_verify_callback(ok, ctx)
int ok;
X509_STORE_CTX *ctx;
#else /* !SSLEAY8 */
client_verify_callback(ok, xs, xi, depth, error)
int ok;
char *xs, *xi;
int depth, error;
#endif /* SSLEAY8 */
{
  /*    X509 *peer; */
    char *subject, *issuer, *cnsubj;
#ifdef SSLEAY8
    int depth,error;
    X509 *xs;

    depth = X509_STORE_CTX_get_error_depth(ctx);
    error = X509_STORE_CTX_get_error(ctx);
    xs = X509_STORE_CTX_get_current_cert(ctx);

#endif /* SSLEAY8 */

    if(ssl_debug_flag && !ok) {
      (void) BIO_printf(bio_err,"ssl:client_verify_callback:depth=%d ok=%d err=%d - %s\r\n",
	      depth,ok,error,X509_verify_cert_error_string(error));
      (void) BIO_flush(bio_err);
    }

    subject=issuer=cnsubj=NULL;

    /* first thing is to have a meaningful name for the current
     * certificate that is being verified ... and if we cannot
     * determine that then something is seriously wrong!
     */
    subject=(char *)ONELINE_NAME(X509_get_subject_name((X509 *)xs));
    if (subject==NULL) {
	ERR_print_errors(bio_err);
	ok=0;
	goto return_time;
    }
    issuer=(char *)ONELINE_NAME(X509_get_issuer_name((X509 *)xs));
    if (issuer==NULL) {
	ERR_print_errors(bio_err);
	ok=0;
	goto return_time;
    }

    /* if the user wants us to be chatty about things then this
     * is a good time to wizz the certificate chain past quickly :-)
     */
    if (ssl_verbose_flag) {
	fprintf(stderr,"Certificate[%d] subject=%s\n",depth,subject);
	fprintf(stderr,"Certificate[%d] issuer =%s\n",depth,issuer);
	fflush(stderr);
    }

    /* verify commonName matches hostname */
    if(ssl_cert_required && depth == 0) {
      char *cn,*p;	
	  
      cnsubj=strdup(subject);
      if(cnsubj == NULL) {
	fprintf(stderr,"SSL: Out of memory.\n");
	ok=0;
	goto return_time;
      }
      cn=strstr(cnsubj,"/CN=");
      if(cn == NULL) {
	fprintf(stderr,"SSL: Cannot extract CN from certificate subject.\n");
	ok=0;
	goto return_time;
      }
      cn+=4; /* skip /CN= */
      p=strchr(cn,'/');
      if(p != NULL) {
	*p='\0';
      }
      if(strcasecmp(cn,RemoteHostName) != 0) {
	fprintf(stderr,"SSL: Certificate CN (%s) does not match hostname (%s)\n",
		cn,RemoteHostName);
	ok=0;
	goto return_time;
      }
    }

    if((error==VERIFY_OK) || (error==VERIFY_ROOT_OK)) {
      goto return_time;
    }

    switch(error) {
    case VERIFY_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      fprintf(stderr,"SSL: Server has a self-signed certificate\n");
      fprintf(stderr, "SSL: unknown Issuer: %s\n", issuer);
      break;
    case VERIFY_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      fprintf(stderr, "SSL: Server uses self-signed certificate in chain.\n");
      fprintf(stderr, "SSL: unknown Issuer: %s\n", issuer);
      break;
    case VERIFY_ERR_UNABLE_TO_GET_ISSUER:
      fprintf(stderr,"SSL: unknown issuer: %s\n",issuer);
      break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
      fprintf(stderr,"SSL: Certificate not yet valid\n");
      BIO_printf(bio_err,"notBefore=");
      ASN1_TIME_print(bio_err, X509_get_notBefore((X509 *) xs));
      BIO_printf(bio_err,"\n");
      break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
      fprintf(stderr,"SSL: Error in certificate notBefore field\n");
      BIO_printf(bio_err,"notBefore=");
      ASN1_TIME_print(bio_err, X509_get_notBefore((X509 *) xs));
      BIO_printf(bio_err,"\n");
      break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
      fprintf(stderr,"SSL: Certificate has expired\n");
      BIO_printf(bio_err,"notAfter=");
      ASN1_TIME_print(bio_err, X509_get_notAfter((X509 *) xs));
      BIO_printf(bio_err,"\n");
      break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
      fprintf(stderr,"SSL: Error in certificate notAfter field\n");
      BIO_printf(bio_err,"notAfter=");
      ASN1_TIME_print(bio_err, X509_get_notAfter((X509 *) xs));
      BIO_printf(bio_err,"\n");
      break;
    default:
      fprintf(stderr,"SSL: %s (%d)\n", X509_verify_cert_error_string(error),error);
      break;
    }

    /* If we are here there was an error */
    ok=0;
    
return_time: ;

    /* clean up things */
    if (subject!=NULL)
	free(subject);
    if (issuer!=NULL)
	free(issuer);
    if (cnsubj!=NULL)
	free(cnsubj);
    if(!ok && ssl_cert_required) {
      if(ssl_debug_flag) {
	(void) BIO_printf(bio_err,"SSL: debug -> ignoring cert required!\n");
	(void) BIO_flush(bio_err);
	ok=1;
      }
      else {
	fprintf(stderr,"SSL: Rejecting connection\n");
	ok=0;
      }
    }
    fflush(stderr);
      
    return ok;
}

/* To be used by server when ssl_only_flag is set.  */
int
ssl_only_verify_callback(int ok, X509_STORE_CTX *ctx)
{
    static char *saved_subject = NULL;
    char *subject;
    int err, depth;
    X509 *cert;

    cert  = X509_STORE_CTX_get_current_cert(ctx);
    err   = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

# ifdef EXTRA_DEBUGGING
    if (ssl_debug_flag) {
	(void) BIO_printf(bio_err, "Verify callback: depth %d, err %d, %s\r\n",
			  depth, err, X509_verify_cert_error_string(err));
	(void) BIO_flush(bio_err);
    }
# endif /* EXTRA_DEBUGGING */

    subject = ONELINE_NAME(X509_get_subject_name(cert));
    if (subject == NULL) {
	ok = 0;

	if (ssl_debug_flag) 
	    (void) BIO_printf(bio_err, "Subject name: %s\r\n",
			      ERR_reason_error_string(ERR_peek_error()));
    }

    if (depth == 0 && subject) {
	free(auth_ssl_name);
	free(saved_subject);
	auth_ssl_name = saved_subject = NULL;

	if (ok)
	    saved_subject = strdup(subject);

	/* Check to see if the certsok list contains this
	 * particular certificate subject.
	 */
	if (ssl_certsok_flag && ssl_cert_required) {
	    char buf[2048];
	    FILE *fp = fopen(SSL_USERS_FILE, "r");

	    if (!fp) {
		/* Missing file is treated as verification failure.  */
		ok = 0;
		SSL_set_verify_result(ssl_con, VERIFY_REJECTED_BY_CERTSOK);
		if (ssl_debug_flag)
		    (void) BIO_printf(bio_err, "Accessing %s: %s\r\n",
				      SSL_USERS_FILE, strerror(errno));
	    } else {
		while(fgets(buf, sizeof(buf), fp)) {
		    char *p;

		    if ((p = strchr(buf, '\n')))
			*p = '\0';

		    p = buf;

		    while (*p && strchr(" \t", *p))
			p++;

		    if (*p == '#')
			continue;

		    p = strchr(buf, ':');
		    if (!p)
			continue;

		    if (strcmp(++p, subject) == 0)
			/* An acceptable subject has been found.  */
			break;
		}

		if (feof(fp)) {
		    /* The file is at EOF, so no acceptable subject name
		     * was included.  Treat this as verification failure.
		     */
		    ok = 0;
		    SSL_set_verify_result(ssl_con, VERIFY_REJECTED_BY_CERTSOK);

		    if (ssl_debug_flag)
			(void) BIO_printf(bio_err, "Rejected by certsok: %s\r\n",
					  subject);
		} else if (ssl_debug_flag)
		    (void) BIO_printf(bio_err, "Certsok found: %s\r\n",
				      subject);

		fclose(fp);
	    }
	}
    }

    /* Depth zero is examined as the very last chained certificate.
     * An acceptable verification makes the subject name relevant.
     */
    if (ok && (err == VERIFY_ROOT_OK) && (depth == 0)) {
	auth_ssl_name = saved_subject;
	saved_subject = NULL;
    }

    free(subject);

    return ok;
} /* ssl_only_verify_callback */

#endif /* USE_SSL */


