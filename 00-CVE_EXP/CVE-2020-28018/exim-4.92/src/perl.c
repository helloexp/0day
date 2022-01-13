/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) 1998 Malcolm Beattie */
/* Copyright (C) 1999 - 2018  Exim maintainers */

/* Modified by PH to get rid of the "na" usage, March 1999.
   Modified further by PH for general tidying for Exim 4.
   Threaded Perl support added by Stefan Traby, Nov 2002
*/


/* This Perl add-on can be distributed under the same terms as Exim itself. */
/* See the file NOTICE for conditions of use and distribution. */

#include <assert.h>
#include "exim.h"

#define EXIM_TRUE TRUE
#undef TRUE

#define EXIM_FALSE FALSE
#undef FALSE

#define EXIM_DEBUG DEBUG
#undef DEBUG

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#ifndef ERRSV
#define ERRSV (GvSV(errgv))
#endif

/* Some people like very old perl versions, so avoid any build side-effects. */

#ifndef pTHX
# define pTHX
# define pTHX_
#endif
#ifndef EXTERN_C
# define EXTERN_C extern
#endif

EXTERN_C void boot_DynaLoader(pTHX_ CV *cv);


static PerlInterpreter *interp_perl = 0;

XS(xs_expand_string)
{
  dXSARGS;
  uschar *str;
  STRLEN len;

  if (items != 1)
    croak("Usage: Exim::expand_string(string)");

  str = expand_string(US SvPV(ST(0), len));
  ST(0) = sv_newmortal();
  if (str != NULL)
    sv_setpv(ST(0), CCS  str);
  else if (!f.expand_string_forcedfail)
    croak("syntax error in Exim::expand_string argument: %s",
      expand_string_message);
}

XS(xs_debug_write)
{
  dXSARGS;
  STRLEN len;
  if (items != 1)
    croak("Usage: Exim::debug_write(string)");
  debug_printf("%s", US SvPV(ST(0), len));
}

XS(xs_log_write)
{
  dXSARGS;
  STRLEN len;
  if (items != 1)
    croak("Usage: Exim::log_write(string)");
  log_write(0, LOG_MAIN, "%s", US SvPV(ST(0), len));
}

static void  xs_init(pTHX)
{
  char *file = __FILE__;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
  newXS("Exim::expand_string", xs_expand_string, file);
  newXS("Exim::debug_write", xs_debug_write, file);
  newXS("Exim::log_write", xs_log_write, file);
}

uschar *
init_perl(uschar *startup_code)
{
  static int argc = 1;
  static char *argv[4] = { "exim-perl" };
  SV *sv;
  STRLEN len;

  if (opt_perl_taintmode) argv[argc++] = "-T";
  argv[argc++] = "/dev/null";
  argv[argc] = 0;

  assert(sizeof(argv)/sizeof(argv[0]) > argc);

  if (interp_perl) return 0;
  interp_perl = perl_alloc();
  perl_construct(interp_perl);
  perl_parse(interp_perl, xs_init, argc, argv, 0);
  perl_run(interp_perl);
    {
    dSP;

    /*********************************************************************/
    /* These lines by PH added to make "warn" output go to the Exim log; I
    hope this doesn't break anything. */

    sv = newSVpv(
      "$SIG{__WARN__} = sub { my($s) = $_[0];"
      "$s =~ s/\\n$//;"
      "Exim::log_write($s) };", 0);
    PUSHMARK(SP);
    perl_eval_sv(sv, G_SCALAR|G_DISCARD|G_KEEPERR);
    SvREFCNT_dec(sv);
    if (SvTRUE(ERRSV)) return US SvPV(ERRSV, len);
    /*********************************************************************/

    sv = newSVpv(CS startup_code, 0);
    PUSHMARK(SP);
    perl_eval_sv(sv, G_SCALAR|G_DISCARD|G_KEEPERR);
    SvREFCNT_dec(sv);
    if (SvTRUE(ERRSV)) return US SvPV(ERRSV, len);

    setlocale(LC_ALL, "C");    /* In case it got changed */
    return NULL;
    }
}

void
cleanup_perl(void)
{
  if (!interp_perl)
    return;
  perl_destruct(interp_perl);
  perl_free(interp_perl);
  interp_perl = 0;
}

gstring *
call_perl_cat(gstring * yield, uschar **errstrp, uschar *name, uschar **arg)
{
  dSP;
  SV *sv;
  STRLEN len;
  uschar *str;
  int items;

  if (!interp_perl)
    {
    *errstrp = US"the Perl interpreter has not been started";
    return 0;
    }

  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  while (*arg != NULL) XPUSHs(newSVpv(CS (*arg++), 0));
  PUTBACK;
  items = perl_call_pv(CS name, G_SCALAR|G_EVAL);
  SPAGAIN;
  sv = POPs;
  PUTBACK;
  if (SvTRUE(ERRSV))
    {
    *errstrp = US SvPV(ERRSV, len);
    return NULL;
    }
  if (!SvOK(sv))
    {
    *errstrp = 0;
    return NULL;
    }
  str = US SvPV(sv, len);
  yield = string_catn(yield, str, (int)len);
  FREETMPS;
  LEAVE;

  setlocale(LC_ALL, "C");    /* In case it got changed */
  return yield;
}

/* End of perl.c */
