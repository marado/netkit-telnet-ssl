/*
 * Copyright (c) 2000 David A. Holland.
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
 *	This product includes software developed by David A. Holland.
 * 4. Neither the name of the Author nor the names of any contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND ANY CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR ANY CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

char copyright[] =
 "@(#) Copyright (c) 2000 David A. Holland.\n"
 "All rights reserved.\n";

char rcsid[] =
  "$Id: telnetlogin.c,v 1.1 2000/04/13 01:07:22 dholland Exp $";
#include "../version.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>
#include <paths.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifndef _PATH_LOGIN
#define _PATH_LOGIN "/bin/login"
#endif

static const char *remhost = NULL;

static void die(const char *fmt, ...) {
   va_list ap;
   fprintf(stderr, "telnetlogin: ");
   va_start(ap, fmt);
   vfprintf(stderr, fmt, ap);
   va_end(ap);
   fprintf(stderr, "\n");
   exit(1);
}

static int check_a_hostname(char *hname) {
   int i=0;
   /* should we check length? */
   for (i=0; hname[i]; i++) {
      if (hname[i]<=32 && hname[i]>126) return -1;
   }
   return 0;
}

static int check_term(char *termtype) {
   int i;
   if (strlen(termtype) > 32) return -1;
   for (i=0; termtype[i]; i++) {
      if (!isalnum(termtype[i]) && !strchr("+._-", termtype[i])) return -1;
   }
   return 0;
}

static int check_display(char *disp) {
   char *colon, *s;
   struct hostent *hp;
   int num;

   colon = strchr(disp, ':');
   if (!colon) return -1;
   *colon = 0;  /* temporarily */

   if (check_a_hostname(disp)) return -1;

   hp = gethostbyname(disp);
   if (!hp) return -1;

   *colon = ':';
   s = colon+1;
   while (*s && isdigit(*s)) s++;
   if (*s) {
      if (*s!='.') return -1;
      s++;
      while (*s && isdigit(*s)) s++;
   }
   if (*s) return -1;

   num = atoi(colon+1);
   if (num<0 || num>99) return -1;

   return 0;
}

static int check_posixly_correct(char *val) {
   if (strlen(val)==0 || !strcmp(val, "1")) return 0;
   return -1;
}

static int check_remotehost(char *val) {
   if (check_a_hostname(val)) return -1;
   if (remhost && strcmp(val, remhost)) return -1;
   return 0;
}

struct {
   const char *name;
   int (*validator)(char *);
} legal_envs[] = {
   { "TERM", check_term },
   { "DISPLAY", check_display },
   { "POSIXLY_CORRECT", check_posixly_correct },
   { "REMOTEHOST", check_remotehost },
   { NULL, NULL }
};

static void validate_tty(void) {
   struct stat buf, buf2;
   const char *tty;
   pid_t pgrp;

   tty = ttyname(0);
   if (!tty) die("stdin not a tty");

   if (fstat(0, &buf)) die("fstat stdin");
   if (!S_ISCHR(buf.st_mode)) die("stdin not char device");

   if (fstat(1, &buf2)) die("fstat stdout");
   if (!S_ISCHR(buf2.st_mode)) die("stdout not char device");
   if (buf.st_rdev!=buf2.st_rdev) die("stdout and stdin not same tty");

   if (fstat(2, &buf2)) die("fstat stderr");
   if (!S_ISCHR(buf2.st_mode)) die("stderr not char device");
   if (buf.st_rdev!=buf2.st_rdev) die("stderr and stdin not same tty");
   
   if (ioctl(0, TIOCGPGRP, &pgrp)) die("cannot get tty process group");
   if (pgrp != getpgrp()) die("not foreground pgrp of tty");
   if (pgrp != getpid()) die("not process group leader");
}

int main(int argc, char *argv[]) {
   static char argv0[] = "login";
   int argn, i, j;
   const char *rh = NULL;
   char **envs = __environ;

   /* make as sure as possible no library routines or anything can use it */
   __environ = NULL;

   /* first, make sure our stdin/stdout/stderr are aimed somewhere */
   i = open("/", O_RDONLY);
   if (i<3) {
      /* Oops. Can't even print an error message... */
      exit(100);
   }
   close(i);

   /* check args */
   argn=1;
   if (argc<1) {
      die("Illegal args: argc < 1");
   }
   if (argn < argc && !strcmp(argv[argn], "-h")) {
      argn++;
      if (argn==argc) die("Illegal args: -h requires argument");
      if (check_a_hostname(argv[argn])) die("Illegal remote host specified");
      rh = argv[argn];
      argn++;
   }
   if (argn < argc && !strcmp(argv[argn], "-p")) {
      argn++;
   }
   if (argn < argc) die("Illegal args: too many args");
   argv[0] = argv0;

   /* check environment */
   if (envs) for (i=0; envs[i]; i++) {
      char *testenv = envs[i];
      size_t testlen = strlen(testenv);
      int ok = 0;
      for (j=0; legal_envs[j].name && !ok; j++) {
	 const char *okenv = legal_envs[j].name;
	 size_t oklen = strlen(okenv);

	 if (testlen < oklen) continue;
	 if (testenv[oklen]!='=') continue;
	 if (memcmp(testenv, okenv, oklen)) continue;
	 if (legal_envs[j].validator(testenv+oklen+1)) {
	    die("Invalid environment: bad value for %s", okenv);
	 }
	 ok = 1;
      }
      if (!ok) {
	 die("Illegal environment: forbidden variable");
      }
   }

   /* unignore all signals so they get cleared at exec time */
   for (i=1; i<NSIG; i++) {
      signal(i, SIG_DFL);
   }

   /* just in case */
   if (chdir("/")) die("chdir to / failed");

   /* 
    * don't do anything with uids and gids, as login is normally meant
    * to be able to take care of them.  
    * 
    * but, should we insist that ruid==nobody?
    */

   /*
    * don't do anything with limits, itimers, or process priority either
    */

   /*
    * should we check to make sure stdin=stdout=stderr and they're a tty
    * and it's our controlling tty [hard] and we're the leader of the 
    * foreground process group?
    *
    * Yeah, we should.
    */
   validate_tty();

   /*
    * now exec login
    * argv[0] was set up above.
    */
   execve(_PATH_LOGIN, argv, envs);
   exit(255);
}
