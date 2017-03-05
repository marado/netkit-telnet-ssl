/* sslapp.h	- ssl application code */

/*
 * The modifications to support SSLeay were done by Tim Hudson
 * tjh@cryptsoft.com
 *
 * You can do whatever you like with these patches except pretend that
 * you wrote them.
 *
 * Email ssl-users-request@mincom.oz.au to get instructions on how to
 * join the mailing list that discusses SSLeay and also these patches.
 *
 */

#ifdef USE_SSL

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

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
#define OLDPROTO NOPROTO
#define NOPROTO
#include "bio.h"
#undef NOPROTO
#define NOPROTO OLDPROTO
#undef OLDPROTO
#endif
#include "buffer.h"

#include "x509.h"
#include "ssl.h"
#define OLDPROTO NOPROTO
#undef NOPROTO
#define NOPROTO
#include "err.h"
#undef NOPROTO
#define NOPROTO OLDPROTO
#undef OLDPROTO

extern BIO *bio_err;
extern SSL *ssl_con;
extern SSL_CTX *ssl_ctx;
extern int ssl_debug_flag;
extern int ssl_only_flag;
extern int ssl_active_flag;
extern int ssl_verify_flag;
extern int ssl_secure_flag;
extern int ssl_verbose_flag;
extern int ssl_disabled_flag;
extern int ssl_cert_required;
extern int ssl_certsok_flag;

extern char *ssl_log_file; 
extern char *ssl_cacert_file; 
extern char *ssl_cert_file; 
extern char *ssl_key_file;
extern char *ssl_cipher_list;

/* we hide all the initialisation code in a separate file now */
extern int do_ssleay_init(int server);

extern void display_connect_details(SSL *ssl_con, int verbose);
extern int server_verify_callback();
extern int client_verify_callback();
extern int ssl_only_verify_callback();

#ifdef __cplusplus
}
#endif

#endif /* USE_SSL */


