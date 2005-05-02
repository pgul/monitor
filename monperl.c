#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif
#include "monitor.h"

#ifndef pTHX_
#define pTHX_
#endif
#ifndef pTHX
#define pTHX
#endif

static PerlInterpreter *perl = NULL;

void boot_DynaLoader(pTHX_ CV *cv);

static void xs_init(pTHX)
{
  static char *file = __FILE__;
  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

void exitperl(void)
{
  if (perl)
  {
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
  }
}

int PerlStart(char *perlfile)
{
  int rc;
  char *perlargs[]={"", "", NULL};

  perlargs[1] = perlfile;
  if (access(perlfile, R_OK))
  { printf("Can't read %s: %s", perlfile, strerror(errno));
    return 1;
  }
  perl = perl_alloc();
  perl_construct(perl);
  rc=perl_parse(perl, xs_init, 2, perlargs, NULL);
  if (rc)
  { printf("Can't parse %s", perlfile);
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
    return 1;
  }
  atexit(exitperl);
  return 0;
}

void plstart(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstart, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

void plstop(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstop, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

void plwrite(char *user, char *src, char *dst, char *direct, int bytes)
{
  SV *svuser, *svsrc, *svdst, *svdirect, *svbytes;
  STRLEN n_a;

  dSP;
  svuser   = perl_get_sv("user",      TRUE);
  svsrc    = perl_get_sv("src",       TRUE);
  svdst    = perl_get_sv("dst",       TRUE);
  svdirect = perl_get_sv("direction", TRUE);
  svbytes  = perl_get_sv("bytes",     TRUE);
  sv_setpv(svuser,   user  );
  sv_setpv(svsrc,    src   );
  sv_setpv(svdst,    dst   );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlwrite, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

void plwritemac(char *mac, char *ua, char *direct, int bytes)
{
  SV *svmac, *svua, *svdirect, *svbytes;
  STRLEN n_a;

  dSP;
  svmac    = perl_get_sv("mac",       TRUE);
  svua     = perl_get_sv("ua",        TRUE);
  svdirect = perl_get_sv("direction", TRUE);
  svbytes  = perl_get_sv("bytes",     TRUE);
  sv_setpv(svmac,    mac   );
  sv_setpv(svua,     ua    );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlwritemac, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

void perl_call(char *file, const char *func, char **args)
{
  STRLEN n_a;

  if (PerlStart(file))
    return;
  {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    while (*args)
    {
      XPUSHs(sv_2mortal(newSVpv(*args, 0)));
      args++;
    }
    PUTBACK;
    perl_call_pv(func, G_EVAL|G_SCALAR);
    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV))
      warning("Perl eval error: %s", SvPV(ERRSV, n_a));
    exitperl();
  }
}
