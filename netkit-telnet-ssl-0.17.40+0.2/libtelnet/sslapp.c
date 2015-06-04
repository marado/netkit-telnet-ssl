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

#include "sslapp.h"

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
char *ssl_cert_file=NULL;
char *ssl_key_file=NULL;
char *ssl_cipher_list=NULL;
char *ssl_log_file=NULL;

/* fwd decl */
static void client_info_callback();

int do_ssleay_init(int server)
{
  /* make sure we have somewhere we can log errors to */
  if (bio_err==NULL) {
    if ((bio_err=BIO_new(BIO_s_file()))!=NULL) {
      if (ssl_log_file==NULL)
	BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);
      else {
	if (BIO_write_filename(bio_err,ssl_log_file)<=0) {
	  /* not a lot we can do */
	}
      }
    }
  }

  /* rather simple things these days ... the old SSL_LOG and SSL_ERR
   * vars are long gone now SSLeay8 has rolled around and we have 
   * a clean interface for doing things
   */
  if (ssl_debug_flag)
    BIO_printf(bio_err,"SSL_DEBUG_FLAG on\r\n");


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
    ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_method());
    if (SSL_CTX_need_tmp_RSA(ssl_ctx)) {
      RSA *rsa;

      if (ssl_debug_flag)
	  BIO_printf(bio_err,"Generating temp (512 bit) RSA key ...\r\n");
      rsa=RSA_generate_key(512,RSA_F4,NULL,NULL);
      if (ssl_debug_flag)
	  BIO_printf(bio_err,"Generation of temp (512 bit) RSA key done\r\n");
   
      if (!SSL_CTX_set_tmp_rsa(ssl_ctx,rsa)) {
	BIO_printf(bio_err,"Failed to assign generated temp RSA key!\r\n");
      }
      RSA_free(rsa);
      if (ssl_debug_flag)
	  BIO_printf(bio_err,"Assigned temp (512 bit) RSA key\r\n");
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

  ssl_con=(SSL *)SSL_new(ssl_ctx);

  SSL_set_verify(ssl_con,ssl_verify_flag,NULL);

/*
  if (ssl_cipher_list==NULL)
      SSL_set_pref_cipher(ssl_con,getenv("SSL_CIPHER"));
  else
      SSL_set_pref_cipher(ssl_con,ssl_cipher_list);
*/

  /* for verbose we use the 0.6.x info callback that I got
   * eric to finally add into the code :-) --tjh
   */
  if (ssl_verbose_flag) {
      SSL_CTX_set_info_callback(ssl_ctx,client_info_callback);
  }

  /* Add in any certificates if you want to here ... */
  if (ssl_cert_file) {
      if (!SSL_use_certificate_file(ssl_con, ssl_cert_file, 
		      X509_FILETYPE_PEM)) {
	  BIO_printf(bio_err,"Error loading %s: ",ssl_cert_file);
	  ERR_print_errors(bio_err);
	  BIO_printf(bio_err,"\r\n");
	  return(0);
      } else {
	  if (!ssl_key_file)
	      ssl_key_file = ssl_cert_file;
	  if (!SSL_use_RSAPrivateKey_file(ssl_con, ssl_key_file,
		      X509_FILETYPE_PEM)) {
	      BIO_printf(bio_err,"Error loading %s: ",ssl_key_file);
	      ERR_print_errors(bio_err);
	      BIO_printf(bio_err,"\r\n");
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

  SSL_set_verify(ssl_con,ssl_verify_flag,client_verify_callback);

  return(1);
}


static void client_info_callback(s,where,ret)
SSL *s;
int where;
int ret;
{
  if (where==SSL_CB_CONNECT_LOOP) {
    BIO_printf(bio_err,"SSL_connect:%s %s\r\n",
		    SSL_state_string(s),SSL_state_string_long(s));
  } else if (where==SSL_CB_CONNECT_EXIT) {
    if (ret == 0) {
      BIO_printf(bio_err,"SSL_connect:failed in %s %s\r\n",
	      SSL_state_string(s),SSL_state_string_long(s));
    } else if (ret < 0) {
      BIO_printf(bio_err,"SSL_connect:error in %s %s\r\n",
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

