/*
 * Copyright (c) 1997-8 Andrew G Morgan <morgan@linux.kernel.org>
 * Copyright (c) 1997 Andrew Main <zefram@dcs.warwick.ac.uk>
 *
 * See end of file for Log.
 *
 * This file deals with exchanging internal and textual
 * representations of capability sets.
 */

#define LIBCAP_PLEASE_INCLUDE_ARRAY
#include "libcap.h"

#include <ctype.h>
#include <stdio.h>

/* Maximum output text length (16 per cap) */
#define CAP_TEXT_SIZE    (16*__CAP_BITS)

#define LIBCAP_EFF   01
#define LIBCAP_INH   02
#define LIBCAP_PER   04

/*
 * Parse a textual representation of capabilities, returning an internal
 * representation.
 */

#define setbits(A,B) _setbits((__cap_s *)A, (__cap_s *)B)
static void _setbits(__cap_s *a, __cap_s *b)
{
    int n;
    for (n = __CAP_BLKS; n--; )
	a->_blk[n] |= b->_blk[n];
}

#define clrbits(A,B) _clrbits((__cap_s *)A, (__cap_s *)B)
static void _clrbits(__cap_s *a, __cap_s *b)
{
    int n;
    for (n = __CAP_BLKS; n--; )
	a->_blk[n] &= ~b->_blk[n];
}

static char const *namcmp(char const *str, char const *nam)
{
    while (*nam && tolower((unsigned char)*str) == *nam) {
	str++;
	nam++;
    }
    if (*nam || isalnum((unsigned char)*str) || *str == '_')
	return NULL;
    return str;
}

static int lookupname(char const **strp)
{
    char const *str = *strp;
    if (isdigit(*str)) {
	unsigned long n = strtoul(str, (char **)&str, 0);
	if (n >= __CAP_BITS)
	    return -1;
	*strp = str;
	return n;
    } else {
	char const *s;
	int n;
	for (n = __CAP_BITS; n--; )
	    if (_cap_names[n] && (s = namcmp(str, _cap_names[n]))) {
		*strp = s;
		return n;
	    }
	return -1;
    }
}

cap_t cap_from_text(const char *str)
{
    cap_t res;
    __cap_s allones;
    int n;

    if (str == NULL) {
	_cap_debug("bad argument");
	errno = EINVAL;
	return NULL;
    }

    if (!(res = cap_init()))
	return NULL;
    for (n = __CAP_BLKS; n--; )
	allones._blk[n] = -1;
    _cap_debug("%s", str);

    for (;;) {
	char op;
	int flags = 0, listed=0;
	__cap_s list = {{0}};

	/* skip leading spaces */
	while (isspace((unsigned char)*str))
	    str++;
	if (!*str) {
	    _cap_debugcap("e = ", &res->set.effective);
	    _cap_debugcap("i = ", &res->set.inheritable);
	    _cap_debugcap("p = ", &res->set.permitted);
	    return res;
	}

	/* identify caps specified by this clause */
	if (isalnum((unsigned char)*str) || *str == '_') {
	    for (;;) {
		if (namcmp(str, "all")) {
		    str += 3;
		    list = allones;
		} else {
		    n = lookupname(&str);
		    if (n == -1)
			goto bad;
		    list.raise_cap(n);
		}
		if (*str != ',')
		    break;
		if (!isalnum((unsigned char)*++str) && *str != '_')
		    goto bad;
	    }
	    listed = 1;
	} else if (*str == '+' || *str == '-')
	    goto bad;                    /* require a list of capabilities */
	else
	    list = allones;

	/* identify first operation on list of capabilities */
	op = *str++;
	if (op == '=' && (*str == '+' || *str == '-')) {
	    if (!listed)
		goto bad;
	    op = (*str++ == '+' ? 'P':'M'); /* skip '=' and take next op */
	} else if (op != '+' && op != '-' && op != '=')
	    goto bad;

	/* cycle through list of actions */
	do {
	    _cap_debug("next char = `%c'", *str);
	    if (*str && !isspace(*str)) {
		switch (*str++) {    /* Effective, Inheritable, Permitted */
		case 'e':
		    flags |= LIBCAP_EFF;
		    break;
		case 'i':
		    flags |= LIBCAP_INH;
		    break;
		case 'p':
		    flags |= LIBCAP_PER;
		    break;
		default:
		    goto bad;
		}
	    } else if (op != '=') {
		_cap_debug("only '=' can be followed by space");
		goto bad;
	    }

	    _cap_debug("how to read?");
	    switch (op) {               /* how do we interpret the caps? */
	    case '=':
	    case 'P':                                              /* =+ */
	    case 'M':                                              /* =- */
		clrbits(&res->set.effective,   &list);
		clrbits(&res->set.inheritable, &list);
		clrbits(&res->set.permitted,   &list);
		/* fall through */
		if (op == 'M')
		    goto minus;
	    case '+':
		if (flags & LIBCAP_EFF)
		    setbits(&res->set.effective,   &list);
		if (flags & LIBCAP_INH)
		    setbits(&res->set.inheritable, &list);
		if (flags & LIBCAP_PER)
		    setbits(&res->set.permitted,   &list);
		break;
	    case '-':
	    minus:
	        if (flags & LIBCAP_EFF)
		    clrbits(&res->set.effective,   &list);
		if (flags & LIBCAP_INH)
		    clrbits(&res->set.inheritable, &list);
		if (flags & LIBCAP_PER)
		    clrbits(&res->set.permitted,   &list);
		break;
	    }

	    /* new directive? */
	    if (*str == '+' || *str == '-') {
		if (!listed) {
		    _cap_debug("for + & - must list capabilities");
		    goto bad;
		}
		flags = 0;                       /* reset the flags */
		op = *str++;
		if (!isalpha(*str))
		    goto bad;
	    }
	} while (*str && !isspace(*str));
	_cap_debug("next clause");
    }

bad:
    cap_free(&res);
    errno = EINVAL;
    return NULL;
}

/*
 * Convert an internal representation to a textual one. The textual
 * representation is stored in static memory. It will be overwritten
 * on the next occasion that this function is called.
 */

static int getstateflags(cap_t caps, int capno)
{
    int f = 0;

    if (isset_cap((__cap_s *)(&caps->set.effective),capno))
	f |= LIBCAP_EFF;
    if (isset_cap((__cap_s *)(&caps->set.inheritable),capno))
	f |= LIBCAP_INH;
    if (isset_cap((__cap_s *)(&caps->set.permitted),capno))
	f |= LIBCAP_PER;

    return f;
}

#define CAP_TEXT_BUFFER_ZONE 100

char *cap_to_text(cap_t caps, ssize_t *length_p)
{
    static char buf[CAP_TEXT_SIZE+CAP_TEXT_BUFFER_ZONE];
    char *p;
    int histo[8] = {0};
    int m, n, t;

    /* Check arguments */
    if (!good_cap_t(caps)) {
	errno = EINVAL;
	return NULL;
    }

    _cap_debugcap("e = ", &caps->set.effective);
    _cap_debugcap("i = ", &caps->set.inheritable);
    _cap_debugcap("p = ", &caps->set.permitted);

    for (n = __CAP_BITS; n--; )
	histo[getstateflags(caps, n)]++;

    for (m=t=7; t--; )
	if (histo[t] > histo[m])
	    m = t;

    /* blank is not a valid capability set */
    p = sprintf(buf, "=%s%s%s",
		(m & LIBCAP_EFF) ? "e" : "",
		(m & LIBCAP_INH) ? "i" : "",
		(m & LIBCAP_PER) ? "p" : "" ) + buf;

    for (t = 8; t--; )
	if (t != m && histo[t]) {
	    *p++ = ' ';
	    for (n = 0; n != __CAP_BITS; n++)
		if (getstateflags(caps, n) == t) {
		    if (_cap_names[n])
			p += sprintf(p, "%s,", _cap_names[n]);
		    else
			p += sprintf(p, "%d,", n);
		    if (p - buf > CAP_TEXT_SIZE) {
			errno = ERANGE;
			return NULL;
		    }
		}
	    p--;
	    n = t & ~m;
	    if (n)
		p += sprintf(p, "+%s%s%s",
			     (n & LIBCAP_EFF) ? "e" : "",
			     (n & LIBCAP_INH) ? "i" : "",
			     (n & LIBCAP_PER) ? "p" : "");
	    n = ~t & m;
	    if (n)
		p += sprintf(p, "-%s%s%s",
			     (n & LIBCAP_EFF) ? "e" : "",
			     (n & LIBCAP_INH) ? "i" : "",
			     (n & LIBCAP_PER) ? "p" : "");
	    if (p - buf > CAP_TEXT_SIZE) {
		errno = ERANGE;
		return NULL;
	    }
	}

    _cap_debug("%s", buf);
    if (length_p) {
	*length_p = p - buf;
    }

    return (_libcap_strdup(buf));
}

/*
 * $Log: cap_text.c,v $
 * Revision 1.2  2003-05-15 00:49:13  castaglia
 *
 * Bug#2000 - mod_cap should not use bundled libcap.  This patch updates the
 * bundled libcap; I won't be closing the bug report just yet.
 *
 * Revision 1.1  2003/01/03 02:16:17  jwm
 *
 * Turning mod_linuxprivs into a core module, mod_cap. This is by no means
 * complete.
 *
 * Revision 1.3  2000/07/11 13:36:52  macgyver
 * Minor updates and buffer cleanups.
 *
 * Revision 1.2  1999/09/07 23:14:19  macgyver
 * Updated capabilities library and model.
 *
 * Revision 1.2  1999/04/17 23:25:09  morgan
 * fixes from peeterj
 *
 * Revision 1.1.1.1  1999/04/17 22:16:31  morgan
 * release 1.0 of libcap
 *
 * Revision 1.4  1998/05/24 22:54:09  morgan
 * updated for 2.1.104
 *
 * Revision 1.3  1997/05/04 05:37:00  morgan
 * case sensitvity to capability flags
 *
 * Revision 1.2  1997/04/28 00:57:11  morgan
 * zefram's replacement file with a number of bug fixes from AGM
 *
 * Revision 1.1  1997/04/21 04:32:52  morgan
 * Initial revision
 *
 */
