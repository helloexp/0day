/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; see the file COPYING.LIB.  If
 * not, write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Suite 500, Boston, MA 02110-1335, USA.
 */

/* Required to tell conf.h not to include the standard ProFTPD
 * header files
 */
#define __PROFTPD_SUPPORT_LIBRARY

#include <conf.h>
#include <libsupp.h>

#include <ctype.h>

#if !defined(HAVE_VSNPRINTF) || !defined(HAVE_SNPRINTF)

# if defined(HAVE_FCONVERT) || defined(HAVE_FCVT)
#  ifdef HAVE_FLOATINGPOINT_H
#   include <floatingpoint.h>
#  endif
#  ifndef DECIMAL_STRING_LENGTH
#   define DECIMAL_STRING_LENGTH 512
#  endif
# endif /* HAVE_FCONVERT || HAVE_FCVT */

static size_t strnlen(const char *s, size_t count)
{
  const char *sc;

  for(sc = s; count-- && *sc != '\0'; ++sc) ;

  return sc - s;
}

static int skip_atoi(const char **s)
{
  int i = 0;

  while(isdigit(**s))
    i = i * 10 + *((*s)++) - '0';

  return i;
}

#define ZEROPAD	1
#define SIGN	2
#define PLUS	4
#define SPACE	8
#define LEFT	16
#define SPECIAL	32
#define LARGE	64

static char *number(char *str, long num, int base, int size, int
                    precision, int type, size_t *max_size)
{
  char c,sign,tmp[66] = {'\0'};
  const char *digits="0123456789abcdefghijklmnopqrstuvwxyz";
  int i;
  size_t msize;

  msize = *max_size;

  if(type & LARGE)
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if(type & LEFT)
    type &= ~ZEROPAD;
  if(base < 2 || base > 36)
    return 0;

  c = (type & ZEROPAD) ? '0' : ' ';
  sign = 0;
  if(type & SIGN) {
    if(num < 0) {
      sign = '-';
      num = -num;
      size--;
    } else if(type & PLUS) {
      sign = '+';
      size--;
    } else if(type & SPACE) {
      sign = ' ';
      size--;
    }
  }

  if(type & SPECIAL) {
    if(base == 16)
      size -= 2;
    else if(base == 8)
      size--;
  }

  i = 0;
  if(num == 0)
    tmp[i++] = '0';
  else while(num != 0) {
  	tmp[i++] = digits[((unsigned long) num) % (unsigned) base];
         	num /= base;
  }
  if(i > precision)
    precision = i;

  size -= precision;
  if(!(type & (ZEROPAD+LEFT)))
    while(size-- > 0 && msize) {
      *str++ = ' ';
      msize--;
    }

  if(sign && msize)
    { *str++ = sign; msize--; }

  if(msize) {
    if(type & SPECIAL) {
      if(base == 8)
        { *str++ = '0'; msize--; }
      else if(base == 16) {
        *str++ = '0'; msize--;
        if(msize)
          { *str++ = digits[33]; msize--; }
      }
    }
  }

  if(!(type & LEFT))
    while(size-- > 0 && msize)
      { *str++ = c; msize--; }

  while(i < precision-- && msize)
    { *str++ = '0'; msize--; }

  while(i-- > 0 && msize)
    { *str++ = tmp[i]; msize--; }

  while(size-- > 0 && msize)
    { *str++ = ' '; msize--; }

  *max_size = msize;
  return str;
}


#ifndef HAVE_VSNPRINTF
/*
** This vsnprintf() emulation does not implement the conversions:
**	%e, %E, %g, %G, %wc, %ws
** The %f implementation is limited.
*/
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
  int len;
  unsigned long num;
  int i, base;
  char *str;
  const char *s;

  int flags;
  int dotflag;

  int field_width;
  int precision;

  int qualifier;

  size--;
  for(str = buf; *fmt && size; ++fmt) {
    if(*fmt != '%') {
      *str++ = *fmt;
      size--;
      continue;
    }

    flags = 0;
    dotflag = 0;
    repeat:
      ++fmt;
      switch(*fmt) {
        case '-': flags |= LEFT; goto repeat;
        case '+': flags |= PLUS; goto repeat;
        case ' ': flags |= SPACE; goto repeat;
        case '#': flags |= SPECIAL; goto repeat;
        case '0': flags |= ZEROPAD; goto repeat;
      }

      field_width = -1;
      if(isdigit(*fmt))
        field_width = skip_atoi(&fmt);
      else if(*fmt == '*') {
        ++fmt;
        field_width = va_arg(args,int);
        if(field_width < 0) {
          field_width = - field_width;
          flags |= LEFT;
        }
      }

      precision = -1;
      if(*fmt == '.') {
	dotflag++;
        ++fmt;
        if(isdigit(*fmt))
          precision = skip_atoi(&fmt);
        else if(*fmt == '*') {
          ++fmt;
          precision = va_arg(args,int);
        }
	/* NB: the default precision value is conversion dependent */
      }

      qualifier = -1;
      if(*fmt == 'h' || *fmt == 'l' || *fmt == 'L') {
        qualifier = *fmt;
        ++fmt;
      }

      base = 10;
      switch(*fmt) {
      case 'c':
        if(!(flags & LEFT))
          while(--field_width > 0 && size)
            { *str++ = ' '; size--; }
        if(size)
          { *str++ = (unsigned char)va_arg(args,int); size--; }
        while(--field_width > 0 && size)
          { *str++ = ' '; size--; }
        continue;
      case 's':
        if ( dotflag && precision < 0 )
          precision = 0;
        s = va_arg(args,char*);
        if(!s)
          s = "(null)";

        len = strnlen(s, precision);

        if(!(flags & LEFT))
          while(len < field_width-- && size) {
            *str++ = ' ';
            size--;
          }

        for(i = 0; i < len && size; ++i) {
          *str++ = *s++;
          size--;
        }

	while(len < field_width-- && size) {
          *str++ = ' ';
          size--;
        }

        continue;

      case 'p':
        if ( dotflag && precision < 0 )
          precision = 0;
        if(field_width == -1) {
          field_width = 2 * sizeof(void*);
          flags |= ZEROPAD;
        }
        str = number(str,
                  (unsigned long)va_arg(args,void*),16,
                  field_width, precision, flags, &size);
        continue;

      case 'n':
        if(qualifier == 'l') {
          long *ip = va_arg(args,long*);
          *ip = (str - buf);
        } else {
          int *ip = va_arg(args,int*);
          *ip = (str - buf);
        }
        continue;

      case 'o':
        base = 8;
        break;

      case 'X':
        flags |= LARGE;
      case 'x':
        base = 16;
        break;

      case 'd':
      case 'i':
        flags |= SIGN;
      case 'u':
        break;

# if defined(HAVE_FCONVERT) || defined(HAVE_FCVT)
      case 'f':
	{
		double	dval;
		int	ndigit, decpt, sign;
		char	cvtbuf[DECIMAL_STRING_LENGTH] = {'\0'};
		char	*cbp;

		/* Default FP precision */
		if ( dotflag && precision < 0 )
			precision = 6;
		/* Let's not press our luck too far */
		ndigit = precision < 16 ? precision : 16;

		dval = va_arg(args, double);

		/*
		** If available fconvert() is preferred, but fcvt() is
		** more widely available.  It is included in 4.3BSD,
		** the SUS1 and SUS2 standards, Gnu libc.
		*/
#  if defined(HAVE_FCONVERT)
		cbp = fconvert(dval, ndigit, &decpt, &sign, cvtbuf);
#  elif defined(HAVE_FCVT)
		cbp = fcvt(dval, ndigit, &decpt, &sign);
		sstrncpy(cvtbuf, cbp, sizeof cvtbuf);
		cbp = cvtbuf;
#  endif

		/* XXX Ought to honor field_width, left/right justification */

		/* Result could be "NaN" or "Inf" */
		if ( ! isdigit(*cbp) ) {
			for ( i = 0 ; *cbp != '\0' && size > 0 ; i++ ) {
				*str++ = *cbp++; size--;
			}
			continue;
		}

		if ( size > 0 ) {
			if ( sign ) {
				*str++ = '-'; size--;
			}
			else if ( flags & PLUS ) {
				*str++ = '+'; size--;
			}
			else if ( flags & SPACE ) {
				*str++ = ' '; size--;
			}
		}

		/* Leading zeros, if needed */
		if ( decpt <= 0 && size > 0 ) {
			/* Prepend '0' */
			*str++ = '0'; size--;
		}
		if ( decpt < 0 && size > 0 ) {
			/* Prepend '.' */
			*str++ = '.'; size--;
			for ( i = decpt ; i < 0 && size > 0 ; i++ ) {
				*str++ = '0'; size--;
			}
		}
		/* Significant digits */
		for ( i = 0 ; size > 0 ; i++ ) {
			if ( i == decpt ) {
				if ( *cbp != '\0' ) {
					*str++ = '.'; size--;
					if ( size <= 0 )
						break;
				}
				else {
					/* Tack on "." or ".0"??? */
					break;
				}
			}
			if ( *cbp != '\0' ) {
				*str++ = *cbp++; size--;
			}
			else if ( i < decpt ) {
				*str++ = '0'; size--;
			}
			else {
				/* Tack on "." or ".0"??? */
				break;
			}
		}
	}
	continue;
	/* break; */
# endif /* HAVE_FCONVERT || HAVE_FCVT */

      default:
        if(*fmt != '%')
          *str++ = '%';
        if(*fmt && size)
          { *str++ = *fmt; size--; }
        else
          --fmt;

        continue;
      }

      if(qualifier == 'l')
        num = va_arg(args,unsigned long);
      else if(qualifier == 'h') {
        if(flags & SIGN)
          num = va_arg(args,short);
        else
          num = va_arg(args,unsigned short);
      } else if(flags & SIGN)
        num = va_arg(args,int);
      else
        num = va_arg(args, unsigned int);

      if ( dotflag && precision < 0 )
        precision = 0;

      str = number(str,num,base,field_width,precision,flags,&size);
  }

  *str = '\0';
  return str - buf;
}
#else /* HAVE_VSNPRINTF */
void
pr_os_already_has_vsnprintf(void)
{
}
#endif /* HAVE_VSNPRINTF */

#ifndef HAVE_SNPRINTF
int
snprintf(char *buf, size_t size, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args,fmt);
  i = vsnprintf(buf,size,fmt,args);
  va_end(args);
  return i;
}
#else /* HAVE_SNPRINTF */
void
pr_os_already_has_snprintf(void)
{
}
#endif /* HAVE_SNPRINTF */

#else /* !HAVE_VSNPRINTF || !HAVE_SNPRINTF */
void
pr_os_already_has_snprintf_and_vsnprintf(void)
{
}
#endif  /* !HAVE_VSNPRINTF || !HAVE_SNPRINTF */
