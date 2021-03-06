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
static int plstart_ok, plstop_ok, plwrite_ok, plwritemac_ok;

void boot_DynaLoader(pTHX_ CV *cv);

static void perl_warn_str(char *str)
{ 
  while (str && *str)
  { char *cp = strchr (str, '\n');
    char c  = 0;
    if (cp)
    { c = *cp;
      *cp = 0;
    }
    error("Perl error: %s", str);
    if (!cp)
      break;
    *cp = c;
    str = cp + 1;
  }
}

static void perl_warn_sv (SV *sv)
{ STRLEN n_a;
  char *str = (char *)SvPV(sv, n_a);
  perl_warn_str(str);
}

static XS(perl_warn)
{
  dXSARGS;
  if (items == 1) perl_warn_sv(ST(0));
  XSRETURN_EMPTY;
}

/* handle multi-line perl eval error message */
static void sub_err(char *sub)
{
  STRLEN len;
  char *s, *p;
  p = SvPV(ERRSV, len);
  if (len)
  { s = malloc(len+1);
    strncpy(s, p, len);
    s[len] = '\0';
  }
  else
    s = strdup("(empty error message)");
  if ((p = strchr(s, '\n')) == NULL || p[1] == '\0')
  { if (p) *p = '\0';
    error("Perl %s error: %s", sub, s);
  }
  else
  {
    error("Perl %s error below:", sub);
    while ( *p && (*p != '\n' || *(p+1)) )
    { char *r = strchr(p, '\n');
      if (r)
      { *r = 0;
        error("  %s", p);
        p = r + 1;
      }
      else
      {
        error("  %s", p);
        break;
      }
    }
  }
  free(s);
}

static void xs_init(pTHX)
{
  static char *file = __FILE__;
  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
  newXS("monitor_warn", perl_warn, file);
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
  static char *perlargs[]={"", NULL, NULL, NULL};
  char cmd[256];
  SV *sv;

  perlargs[1] = "-e";
  perlargs[2] = "0";
  if (access(perlfile, R_OK))
  { printf("Can't read %s: %s", perlfile, strerror(errno));
    return 1;
  }
  perl = perl_alloc();
  perl_construct(perl);
  rc=perl_parse(perl, xs_init, 3, perlargs, NULL);
  if (rc)
  { printf("Can't parse %s", perlfile);
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
    return 1;
  }
  /* Set warn and die hooks */
  if (PL_warnhook) SvREFCNT_dec (PL_warnhook);
  if (PL_diehook ) SvREFCNT_dec (PL_diehook );
  PL_warnhook = newRV_inc ((SV*) perl_get_cv ("monitor_warn", TRUE));
  PL_diehook  = newRV_inc ((SV*) perl_get_cv ("monitor_warn", TRUE));
  /* run main program body */
  snprintf(cmd, sizeof(cmd), "do '%s'; $@ ? $@ : '';", perlfile);
  sv = perl_eval_pv (cmd, TRUE);
  if (!SvPOK(sv)) {
    error("Syntax error in internal perl expression: %s", cmd);
    rc = 1;
  } else if (SvTRUE (sv)) {
    perl_warn_sv (sv);
    rc = 1;
  }
  if (rc) {
    perl_destruct(perl);
    perl_free(perl);
    perl = NULL;
    return 0;
  }
  plstart_ok = plstop_ok = plwrite_ok = plwritemac_ok = 0;
  if (perl_get_cv("startwrite", FALSE)) plstart_ok    = 1;
  if (perl_get_cv("stopwrite",  FALSE)) plstop_ok     = 1;
  if (perl_get_cv("write",      FALSE)) plwrite_ok    = 1;
  if (perl_get_cv("writemac",   FALSE)) plwritemac_ok = 1;
  atexit(exitperl);
  return 0;
}

void plstart(void)
{
  dSP;
  if (!plstart_ok) return;
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
    sub_err("startwrite");
}

void plstop(void)
{
  dSP;
  if (!plstop_ok) return;
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
    sub_err("stopwrite");
}

#if NBITS>0
void plwrite(char *user, char *src, char *dst, char *direct,unsigned long bytes)
#else
void plwrite(char *user, unsigned long bytes_in, unsigned long bytes_out)
#endif
{
#if NBITS>0
  SV *svuser, *svsrc, *svdst, *svdirect, *svbytes;
#else
  SV *svuser, *svbytesin, *svbytesout;
#endif

  dSP;
  if (!plwrite_ok) return;
  svuser   = perl_get_sv("user",      TRUE);
#if NBITS>0
  svsrc    = perl_get_sv("src",       TRUE);
  svdst    = perl_get_sv("dst",       TRUE);
  svdirect = perl_get_sv("direction", TRUE);
  svbytes  = perl_get_sv("bytes",     TRUE);
  sv_setpv(svsrc,    src   );
  sv_setpv(svdst,    dst   );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
#else
  svbytesin  = perl_get_sv("bytes_in",  TRUE);
  svbytesout = perl_get_sv("bytes_out", TRUE);
  sv_setiv(svbytesin,  bytes_in);
  sv_setiv(svbytesout, bytes_out);
#endif
  sv_setpv(svuser,   user  );
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
    sub_err("write");
}

#if NBITS>0
void plwritemac(char *mac, char *ua, char *direct, unsigned long bytes)
#else
void plwritemac(char *mac, unsigned long bytes_in, unsigned long bytes_out)
#endif
{
#if NBITS>0
  SV *svmac, *svua, *svdirect, *svbytes;
#else
  SV *svmac, *svbytesin, *svbytesout;
#endif
  STRLEN n_a;

  dSP;
  if (!plwritemac_ok) return;
  svmac    = perl_get_sv("mac",       TRUE);
#if NBITS>0
  svua     = perl_get_sv("ua",        TRUE);
  svdirect = perl_get_sv("direction", TRUE);
  svbytes  = perl_get_sv("bytes",     TRUE);
  sv_setpv(svua,     ua    );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
#else
  svbytesin  = perl_get_sv("bytes_in",  TRUE);
  svbytesout = perl_get_sv("bytes_out", TRUE);
  sv_setiv(svbytesin,  bytes_in);
  sv_setiv(svbytesout, bytes_out);
#endif
  sv_setpv(svmac, mac);
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

void perl_call(char *file, char *func, char **args)
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
