/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Regex management code. */

#include "conf.h"

#ifdef PR_USE_REGEX

#ifdef PR_USE_PCRE
#include <pcre.h>

struct regexp_rec {
  pool *regex_pool;

  /* Owning module */
  module *m;

  /* Copy of the original regular expression pattern */
  const char *pattern;

  /* For callers wishing to use POSIX REs */
  regex_t *re;

  /* For callers wishing to use PCRE REs */
  pcre *pcre;
  pcre_extra *pcre_extra;

  const char *pcre_errstr;
};

static unsigned long pcre_match_limit = 0;
static unsigned long pcre_match_limit_recursion = 0;

#else /* !PR_USE_PCRE */
struct regexp_rec {
  pool *regex_pool;

  /* Owning module */
  module *m;

  /* Copy of the original regular expression pattern */
  const char *pattern;

  /* For callers wishing to use POSIX REs */
  regex_t *re;
};

#endif /* PR_USE_PCRE */

static pool *regexp_pool = NULL;
static array_header *regexp_list = NULL;

static const char *trace_channel = "regexp";

static void regexp_free(pr_regex_t *pre) {
#ifdef PR_USE_PCRE
  if (pre->pcre != NULL) {
# if defined(HAVE_PCRE_PCRE_FREE_STUDY)
    pcre_free_study(pre->pcre_extra);
# endif /* HAVE_PCRE_PCRE_FREE_STUDY */
    pre->pcre_extra = NULL;
    pcre_free(pre->pcre);
    pre->pcre = NULL;
  }
#endif /* PR_USE_PCRE */

  if (pre->re != NULL) {
    /* This frees memory associated with this pointer by regcomp(3). */
    regfree(pre->re);
    pre->re = NULL;
  }

  pre->pattern = NULL;
  destroy_pool(pre->regex_pool);
}

static void regexp_cleanup(void) {
  /* Only perform this cleanup if necessary */
  if (regexp_pool) {
    register unsigned int i = 0;
    pr_regex_t **pres = (pr_regex_t **) regexp_list->elts;

    for (i = 0; i < regexp_list->nelts; i++) {
      if (pres[i] != NULL) {
        regexp_free(pres[i]);
        pres[i] = NULL;
      }
    }

    destroy_pool(regexp_pool);
    regexp_pool = NULL;
    regexp_list = NULL;
  }
}

static void regexp_exit_ev(const void *event_data, void *user_data) {
  regexp_cleanup();
  return;
}

static void regexp_restart_ev(const void *event_data, void *user_data) {
  regexp_cleanup();
  return;
}

pr_regex_t *pr_regexp_alloc(module *m) {
  pr_regex_t *pre = NULL;
  pool *re_pool = NULL;

  /* If no regex-tracking list has been allocated, create one.  Register a
   * cleanup handler for this pool, to free up the data in the list.
   */
  if (regexp_pool == NULL) {
    regexp_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(regexp_pool, "Regexp Pool");
    regexp_list = make_array(regexp_pool, 0, sizeof(pr_regex_t *));
  }

  re_pool = pr_pool_create_sz(regexp_pool, 128);
  pr_pool_tag(re_pool, "regexp pool");

  pre = pcalloc(re_pool, sizeof(pr_regex_t));
  pre->regex_pool = re_pool;
  pre->m = m;

  /* Add this pointer to the array. */
  *((pr_regex_t **) push_array(regexp_list)) = pre;

  return pre;
}

void pr_regexp_free(module *m, pr_regex_t *pre) {
  register unsigned int i = 0;
  pr_regex_t **pres = NULL;

  if (regexp_list == NULL) {
    return;
  }

  pres = (pr_regex_t **) regexp_list->elts;

  for (i = 0; i < regexp_list->nelts; i++) {
    if (pres[i] == NULL) {
      continue;
    }

    if ((pre != NULL && pres[i] == pre) ||
        (m != NULL && pres[i]->m == m)) {
      regexp_free(pres[i]);
      pres[i] = NULL;
    }
  }
}

#ifdef PR_USE_PCRE
static int regexp_compile_pcre(pr_regex_t *pre, const char *pattern,
    int flags) {
  int err_offset, study_flags = 0;

  if (pre == NULL ||
      pattern == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "compiling pattern '%s' into PCRE regex",
    pattern);
  pre->pattern = pstrdup(pre->regex_pool, pattern);

  pre->pcre = pcre_compile(pattern, flags, &(pre->pcre_errstr), &err_offset,
    NULL);
  if (pre->pcre == NULL) {
    pr_trace_msg(trace_channel, 4,
      "error compiling pattern '%s' into PCRE regex: %s", pattern,
      pre->pcre_errstr);
    return -1;
  }

  /* Study the pattern as well, just in case. */
#ifdef PCRE_STUDY_JIT_COMPILE
  study_flags = PCRE_STUDY_JIT_COMPILE;
#endif /* PCRE_STUDY_JIT_COMPILE */
  pr_trace_msg(trace_channel, 9, "studying pattern '%s' for PCRE extra data",
    pattern);
  pre->pcre_extra = pcre_study(pre->pcre, study_flags, &(pre->pcre_errstr));
  if (pre->pcre_extra == NULL) {
    if (pre->pcre_errstr != NULL) {
      pr_trace_msg(trace_channel, 4,
        "error studying pattern '%s' for PCRE regex: %s", pattern,
        pre->pcre_errstr);
    }
  }

  return 0;
}
#endif /* PR_USE_PCRE */

int pr_regexp_compile_posix(pr_regex_t *pre, const char *pattern, int flags) {
  int res;

  if (pre == NULL ||
      pattern == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (pre->re != NULL) {
    regfree(pre->re);
    pre->re = NULL;
  }

  pr_trace_msg(trace_channel, 9, "compiling pattern '%s' into POSIX regex",
    pattern);
  pre->pattern = pstrdup(pre->regex_pool, pattern);

  pre->re = pcalloc(pre->regex_pool, sizeof(regex_t));
  res = regcomp(pre->re, pattern, flags);

  return res;
}

int pr_regexp_compile(pr_regex_t *pre, const char *pattern, int flags) {
#ifdef PR_USE_PCRE
  int pcre_flags = 0;

  /* Provide a simple mapping of POSIX regcomp(3) flags to
   * PCRE pcre_compile() flags.  The ProFTPD code tends not to use many
   * of these flags.
   */
  if (flags & REG_ICASE) {
    pcre_flags |= PCRE_CASELESS;
  }

  return regexp_compile_pcre(pre, pattern, pcre_flags);
#else
  return pr_regexp_compile_posix(pre, pattern, flags);
#endif /* PR_USE_PCRE */
}

size_t pr_regexp_error(int errcode, const pr_regex_t *pre, char *buf,
    size_t bufsz) {
  size_t res = 0;

  if (pre == NULL ||
      buf == NULL ||
      bufsz == 0) {
    return 0;
  }

#ifdef PR_USE_PCRE
  if (pre->pcre_errstr != NULL) {
    sstrncpy(buf, pre->pcre_errstr, bufsz);
    return strlen(pre->pcre_errstr) + 1; 
  }
#endif /* PR_USE_PCRE */

  if (pre->re != NULL) {
    /* Make sure the given buffer is always zeroed out first. */
    memset(buf, '\0', bufsz);
    res = regerror(errcode, pre->re, buf, bufsz-1);
  }

  return res;
}

const char *pr_regexp_get_pattern(const pr_regex_t *pre) {
  if (pre == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (pre->pattern == NULL) {
    errno = ENOENT;
    return NULL;
  }

  return pre->pattern;
}

#ifdef PR_USE_PCRE
static int regexp_exec_pcre(pr_regex_t *pre, const char *str,
    size_t nmatches, regmatch_t *matches, int flags, unsigned long match_limit,
    unsigned long match_limit_recursion) {

  if (pre->pcre != NULL) {
    int res;
    size_t str_len;

    str_len = strlen(str);

    /* Use the default match limits, if set and if the caller did not
     * explicitly provide limits.
     */
    if (match_limit == 0) {
      match_limit = pcre_match_limit;
    }

    if (match_limit_recursion == 0) {
      match_limit_recursion = pcre_match_limit_recursion;
    }

    if (match_limit > 0) {
      if (pre->pcre_extra == NULL) {
        pre->pcre_extra = pcalloc(pre->regex_pool, sizeof(pcre_extra));
      }

      pre->pcre_extra->flags |= PCRE_EXTRA_MATCH_LIMIT;
      pre->pcre_extra->match_limit = match_limit;
    }

    if (match_limit_recursion > 0) {
      if (pre->pcre_extra == NULL) {
        pre->pcre_extra = pcalloc(pre->regex_pool, sizeof(pcre_extra));
      }

      pre->pcre_extra->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
      pre->pcre_extra->match_limit_recursion = match_limit_recursion;
    }

    pr_trace_msg(trace_channel, 9,
      "executing PCRE regex '%s' against subject '%s'",
      pr_regexp_get_pattern(pre), str);
    res = pcre_exec(pre->pcre, pre->pcre_extra, str, str_len, 0, flags,
      NULL, 0);

    if (res < 0) {
      if (pr_trace_get_level(trace_channel) >= 9) {
        const char *reason = "unknown";

        switch (res) {
          case PCRE_ERROR_NOMATCH:
            reason = "subject did not match pattern";
            break;

          case PCRE_ERROR_NULL:
            reason = "null regex or subject";
            break;

          case PCRE_ERROR_BADOPTION:
            reason = "unsupported options bit";
            break;

          case PCRE_ERROR_BADMAGIC:
            reason = "bad magic number in regex";
            break;

          case PCRE_ERROR_UNKNOWN_OPCODE:
          case PCRE_ERROR_INTERNAL:
            reason = "internal PCRE error or corrupted regex";
            break;

          case PCRE_ERROR_NOMEMORY:
            reason = "not enough memory for backreferences";
            break;

          case PCRE_ERROR_MATCHLIMIT:
            reason = "match limit reached/exceeded";
            break;

          case PCRE_ERROR_RECURSIONLIMIT:
            reason = "match limit recursion reached/exceeded";
            break;

          case PCRE_ERROR_BADUTF8:
            reason = "invalid UTF8 subject used";
            break;

          case PCRE_ERROR_PARTIAL:
            reason = "subject matched only partially; PCRE_PARTIAL flag not used";
            break;
        }

        pr_trace_msg(trace_channel, 9,
          "PCRE regex '%s' failed to match subject '%s': %s",
          pr_regexp_get_pattern(pre), str, reason);

      } else {
        pr_trace_msg(trace_channel, 9,
          "PCRE regex '%s' successfully match subject '%s'",
          pr_regexp_get_pattern(pre), str);
      }
    }

    return res;
  }

  errno = EINVAL;
  return -1;
}
#endif /* PR_USE_PCRE */

static int regexp_exec_posix(pr_regex_t *pre, const char *str,
    size_t nmatches, regmatch_t *matches, int flags) {
  int res;

  pr_trace_msg(trace_channel, 9,
    "executing POSIX regex '%s' against subject '%s'",
    pr_regexp_get_pattern(pre), str);
  res = regexec(pre->re, str, nmatches, matches, flags);
  return res;
}

int pr_regexp_exec(pr_regex_t *pre, const char *str, size_t nmatches,
    regmatch_t *matches, int flags, unsigned long match_limit,
    unsigned long match_limit_recursion) {
  int res;

  if (pre == NULL ||
      str == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef PR_USE_PCRE
  if (pre->pcre != NULL) {
    return regexp_exec_pcre(pre, str, nmatches, matches, flags, match_limit,
      match_limit_recursion);
  }
#endif /* PR_USE_PCRE */

  res = regexp_exec_posix(pre, str, nmatches, matches, flags);

  /* Make sure that we return a negative value to indicate a failed match;
   * PCRE already does this.
   */
  if (res == REG_NOMATCH) {
    res = -1;
  }

  return res;
}

int pr_regexp_set_limits(unsigned long match_limit,
    unsigned long match_limit_recursion) {

#ifdef PR_USE_PCRE
  pcre_match_limit = match_limit;
  pcre_match_limit_recursion = match_limit_recursion;
#endif

  return 0;
}

void init_regexp(void) {

  /* Register a restart handler for the regexp pool, so that when restarting,
   * regfree(3) is called on each of the regex_t pointers in a
   * regex_t-tracking array, thus preventing memory leaks on a long-running
   * daemon.
   *
   * This registration is done here so that it only happens once.
   */
  pr_event_register(NULL, "core.restart", regexp_restart_ev, NULL);
  pr_event_register(NULL, "core.exit", regexp_exit_ev, NULL);

#ifdef PR_USE_PCRE
  pr_log_debug(DEBUG2, "using PCRE %s", pcre_version());
#endif /* PR_USE_PCRE */
}

#endif
