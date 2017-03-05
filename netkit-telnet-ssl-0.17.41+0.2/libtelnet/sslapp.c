/* sslapp.c	- ssl application code */

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

#include <string.h>
#include <syslog.h>
#include "sslapp.h"

#include <openssl/rand.h>

#ifdef SSLEAY8
#define SSL_set_pref_cipher(c,n)        SSL_set_cipher_list(c,n)
#endif

SSL_CTX *ssl_ctx;
SSL *ssl_con;
int ssl_debug_flag=0;
int ssl_only_flag=0;
int ssl_active_flag=0;
int ssl_verify_flag=SSL_VERIFY_NONE;
int ssl_secure_flag=0;
int ssl_certsok_flag=0;
int ssl_cert_required=0;
int ssl_verbose_flag=0;
int ssl_disabled_flag=0;
char *ssl_cacert_file=NULL;
char *ssl_cert_file=NULL;
char *ssl_key_file=NULL;
char *ssl_cipher_list=NULL;
char *ssl_log_file=NULL;

/* fwd decl */
static void client_info_callback();

int do_ssleay_init(int server)
{
  int ret;

  /* make sure we have somewhere we can log errors to */
  if (bio_err==NULL) {
    if ((bio_err=BIO_new(BIO_s_file()))!=NULL) {
      if (ssl_log_file==NULL)
	BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);
      else {
	if (BIO_write_filename(bio_err,ssl_log_file)<=0) {
	  if (server)
	    syslog(LOG_ERR | LOG_DAEMON, "No access to log file %s.",
		   ssl_log_file);
	  else
	    fprintf(stderr, "No logging allowed to %s.\n", ssl_log_file);
	  /* not a lot we can do */
	}
      }
    }
  }

  /* rather simple things these days ... the old SSL_LOG and SSL_ERR
   * vars are long gone now SSLeay8 has rolled around and we have 
   * a clean interface for doing things
   */
  if (ssl_debug_flag) {
    (void) BIO_printf(bio_err,"SSL_DEBUG_FLAG on\r\n");
    (void) BIO_flush(bio_err);
  }


  /* init things so we will get meaningful error messages
   * rather than numbers 
   */
  SSL_load_error_strings();

#ifdef SSLEAY8
  SSLeay_add_ssl_algorithms();

  /* we may require a temp 512 bit RSA key because of the
   * wonderful way export things work ... if so we generate
   * one now!
   */
  if (server) {
    ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_server_method());
    if (SSL_CTX_need_tmp_RSA(ssl_ctx)) {
      RSA *rsa = NULL;
      BIGNUM *exp = NULL;

      if (ssl_debug_flag)
	  (void) BIO_printf(bio_err,"Generating temp (512 bit) RSA key ...\r\n");

#if OPENSSL_VERSION_NUMBER > 0x00090800fL
      rsa = RSA_new();
      if (rsa == NULL)
	return(0);

      if (ssl_debug_flag && RAND_status() != 1) {
	(void) BIO_printf(bio_err, "Insufficient seeding of PRNG.\r\n");
	(void) BIO_flush(bio_err);
      }

      exp = BN_new();
      if (exp) {
	if (BN_set_word(exp, RSA_F4) == 1)
	  RSA_generate_key_ex(rsa, 512, exp, NULL);
	    
	BN_free(exp);
      }
#else /* Not later than 0.9.8. */
      rsa=RSA_generate_key(512,RSA_F4,NULL,NULL);
#endif
      if (rsa == NULL)
	return(0);

      if (ssl_debug_flag)
	  (void) BIO_printf(bio_err,"Generation of temp (512 bit) RSA key done\r\n");
   
      if (!SSL_CTX_set_tmp_rsa(ssl_ctx,rsa)) {
	(void) BIO_printf(bio_err,"Failed to assign generated temp RSA key!\r\n");
      }
      RSA_free(rsa);
      if (ssl_debug_flag)
	  (void) BIO_printf(bio_err,"Assigned temp (512 bit) RSA key\r\n");
    }
  } else {
    ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_client_method());
  }


  /* also switch on all the interoperability and bug
   * workarounds so that we will communicate with people
   * that cannot read poorly written specs :-)
   */
  SSL_CTX_set_options(ssl_ctx,SSL_OP_ALL);

#else /* !SSLEAY8 */
  ssl_ctx=(SSL_CTX *)SSL_CTX_new();
#endif /* SSLEAY8 */

  /* for verbose we use the 0.6.x info callback that I got
   * eric to finally add into the code :-) --tjh
   */
  if (ssl_verbose_flag) {
      SSL_CTX_set_info_callback(ssl_ctx,client_info_callback);
  }

  /* Add any requested CA certificates.  */
  if (ssl_cacert_file) {
      errno = 0;

      if (!SSL_CTX_load_verify_locations(ssl_ctx, ssl_cacert_file, NULL)) {
	  if (errno)
	      (void) BIO_printf(bio_err, "Error loading CA, %s: %s\r\n",
			 strerror(errno), ssl_cacert_file);
	  else {
	      const char *e = ERR_func_error_string(ERR_peek_error());

	      if (e)
		  (void) BIO_printf(bio_err, "Error loading CA %s: %s, %s\r\n",
			     ssl_cacert_file, e,
			     ERR_reason_error_string(ERR_peek_error()));
	      else
		  (void) BIO_printf(bio_err, "Broken CA file: %s\r\n",
			     ssl_cacert_file);
	      (void) BIO_flush(bio_err);
	  }
	  /* This condition is not desirable, but can only make the
	     chance of later success decrease, not increase!
	   */
	  if (server)
	      syslog(LOG_NOTICE | LOG_DAEMON,
		     "Error while loading CA file %s.", ssl_cacert_file);
      } else if (server) {
	  STACK_OF(X509_NAME) *names;

	  if (ssl_debug_flag)
	      (void) BIO_printf(bio_err, "Preparing client CA list.\r\n");

	  names = SSL_load_client_CA_file(ssl_cacert_file);
	  if (names)
	      SSL_CTX_set_client_CA_list(ssl_ctx, names);
	  else
	      (void) BIO_printf(bio_err, "Failed to load client CA list.\r\n");
      }
  }

  /* Add in any certificates if you want to here ... */
  if (ssl_cert_file) {
      errno = 0;

      if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, ssl_cert_file)) {
	  if (errno) {
	      (void) BIO_printf(bio_err, "Error loading CRT, %s: %s\r\n",
			 strerror(errno), ssl_cert_file);
	  } else {
	      (void) BIO_printf(bio_err, "Error loading CRT %s: %s, %s\r\n",
			 ssl_cert_file,
			 ERR_func_error_string(ERR_peek_error()),
			 ERR_reason_error_string(ERR_peek_error()));
	  }
	  (void) BIO_flush(bio_err);
	  return(0);
      } else {
	  if (!ssl_key_file)
	      ssl_key_file = ssl_cert_file;
	  if (!SSL_CTX_use_RSAPrivateKey_file(ssl_ctx, ssl_key_file,
		      X509_FILETYPE_PEM)) {
	      if (errno) {
		  (void) BIO_printf(bio_err, "Error loading KEY, %s: %s\r\n",
			     strerror(errno), ssl_key_file);
	      } else {
		  (void) BIO_printf(bio_err, "Error loading KEY %s: %s, %s\r\n",
			     ssl_key_file,
			     ERR_func_error_string(ERR_peek_error()),
			     ERR_reason_error_string(ERR_peek_error()));
	      }
	      (void) BIO_flush(bio_err);
	      return(0);
	  }
      }
  }

  /* make sure we will find certificates in the standard
   * location ... otherwise we don't look anywhere for
   * these things which is going to make client certificate
   * exchange rather useless :-)
   */
#ifdef SSLEAY8
  SSL_CTX_set_default_verify_paths(ssl_ctx);
#else
  SSL_set_default_verify_paths(ssl_ctx);
#endif

  /* Now create the connection.  */
  ssl_con=(SSL *)SSL_new(ssl_ctx);

  /* Select the desired cipher suites for the new connection.  */
  ret = 1;
  if (ssl_cipher_list == NULL) {
    char *p = getenv("SSL_CIPHER");

    if (p)
      ret = SSL_set_cipher_list(ssl_con, p);
  } else
      ret = SSL_set_cipher_list(ssl_con, ssl_cipher_list);

  if (!ret)
    return(0);

  SSL_set_verify(ssl_con,ssl_verify_flag,client_verify_callback);

  if (ssl_debug_flag)
    (void) BIO_flush(bio_err);

  return(1);
}


static void client_info_callback(s,where,ret)
SSL *s;
int where;
int ret;
{
  if (where==SSL_CB_CONNECT_LOOP) {
    (void) BIO_printf(bio_err,"SSL_connect:%s %s\r\n",
		    SSL_state_string(s),SSL_state_string_long(s));
  } else if (where==SSL_CB_CONNECT_EXIT) {
    if (ret == 0) {
      (void) BIO_printf(bio_err,"SSL_connect:failed in %s %s\r\n",
	      SSL_state_string(s),SSL_state_string_long(s));
    } else if (ret < 0) {
      (void) BIO_printf(bio_err,"SSL_connect:error in %s %s\r\n",
	      SSL_state_string(s),SSL_state_string_long(s));
    }
  }
}


#else /* !USE_SSL */

static void dummy_func()
{
  int i;

  i++;
}

#endif /* USE_SSL */

