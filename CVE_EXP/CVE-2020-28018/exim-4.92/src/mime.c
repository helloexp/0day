/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004 - 2015
 * License: GPL
 * Copyright (c) The Exim Maintainers 2015 - 2018
 */

#include "exim.h"
#ifdef WITH_CONTENT_SCAN	/* entire file */
#include "mime.h"
#include <sys/stat.h>

FILE *mime_stream = NULL;
uschar *mime_current_boundary = NULL;

static mime_header mime_header_list[] = {
  /*	name			namelen		value */
  { US"content-type:",              13, &mime_content_type },
  { US"content-disposition:",       20, &mime_content_disposition },
  { US"content-transfer-encoding:", 26, &mime_content_transfer_encoding },
  { US"content-id:",                11, &mime_content_id },
  { US"content-description:",       20, &mime_content_description }
};

static int mime_header_list_size = nelem(mime_header_list);

static mime_parameter mime_parameter_list[] = {
  /*	name	namelen	 value */
  { US"name=",     5, &mime_filename },
  { US"filename=", 9, &mime_filename },
  { US"charset=",  8, &mime_charset  },
  { US"boundary=", 9, &mime_boundary }
};


/*************************************************
* set MIME anomaly level + text                  *
*************************************************/

/* Small wrapper to set the two expandables which
   give info on detected "problems" in MIME
   encodings. Indexes are defined in mime.h. */

void
mime_set_anomaly(int idx)
{
struct anom {
  int level;
  const uschar * text;
} anom[] = { {1, CUS"Broken Quoted-Printable encoding detected"},
	     {2, CUS"Broken BASE64 encoding detected"} };

mime_anomaly_level = anom[idx].level;
mime_anomaly_text =  anom[idx].text;
}


/*************************************************
* decode quoted-printable chars                  *
*************************************************/

/* gets called when we hit a =
   returns: new pointer position
   result code in c:
          -2 - decode error
          -1 - soft line break, no char
           0-255 - char to write
*/

static uschar *
mime_decode_qp_char(uschar *qp_p, int *c)
{
uschar *initial_pos = qp_p;

/* advance one char */
qp_p++;

/* Check for two hex digits and decode them */
if (isxdigit(*qp_p) && isxdigit(qp_p[1]))
  {
  /* Do hex conversion */
  *c = (isdigit(*qp_p) ? *qp_p - '0' : toupper(*qp_p) - 'A' + 10) <<4;
  qp_p++;
  *c |= isdigit(*qp_p) ? *qp_p - '0' : toupper(*qp_p) - 'A' + 10;
  return qp_p + 1;
  }

/* tab or whitespace may follow just ignore it if it precedes \n */
while (*qp_p == '\t' || *qp_p == ' ' || *qp_p == '\r')
  qp_p++;

if (*qp_p == '\n')	/* hit soft line break */
  {
  *c = -1;
  return qp_p;
  }

/* illegal char here */
*c = -2;
return initial_pos;
}


/* just dump MIME part without any decoding */
static ssize_t
mime_decode_asis(FILE* in, FILE* out, uschar* boundary)
{
  ssize_t len, size = 0;
  uschar buffer[MIME_MAX_LINE_LENGTH];

  while(fgets(CS buffer, MIME_MAX_LINE_LENGTH, mime_stream) != NULL)
    {
    if (boundary != NULL
       && Ustrncmp(buffer, "--", 2) == 0
       && Ustrncmp((buffer+2), boundary, Ustrlen(boundary)) == 0
       )
      break;

    len = Ustrlen(buffer);
    if (fwrite(buffer, 1, (size_t)len, out) < len)
      return -1;
    size += len;
    } /* while */
  return size;
}



/* decode quoted-printable MIME part */
static ssize_t
mime_decode_qp(FILE* in, FILE* out, uschar* boundary)
{
uschar ibuf[MIME_MAX_LINE_LENGTH], obuf[MIME_MAX_LINE_LENGTH];
uschar *ipos, *opos;
ssize_t len, size = 0;

while (fgets(CS ibuf, MIME_MAX_LINE_LENGTH, in) != NULL)
  {
  if (boundary != NULL
     && Ustrncmp(ibuf, "--", 2) == 0
     && Ustrncmp((ibuf+2), boundary, Ustrlen(boundary)) == 0
     )
    break; /* todo: check for missing boundary */

  ipos = ibuf;
  opos = obuf;

  while (*ipos != 0)
    {
    if (*ipos == '=')
      {
      int decode_qp_result;

      ipos = mime_decode_qp_char(ipos, &decode_qp_result);

      if (decode_qp_result == -2)
	{
	/* Error from decoder. ipos is unchanged. */
	mime_set_anomaly(MIME_ANOMALY_BROKEN_QP);
	*opos++ = '=';
	++ipos;
	}
      else if (decode_qp_result == -1)
	break;
      else if (decode_qp_result >= 0)
	*opos++ = decode_qp_result;
      }
    else
      *opos++ = *ipos++;
    }
  /* something to write? */
  len = opos - obuf;
  if (len > 0)
    {
    if (fwrite(obuf, 1, len, out) != len) return -1; /* error */
    size += len;
    }
  }
return size;
}


/*
 * Return open filehandle for combo of path and file.
 * Side-effect: set mime_decoded_filename, to copy in allocated mem
 */
static FILE *
mime_get_decode_file(uschar *pname, uschar *fname)
{
if (pname && fname)
  mime_decoded_filename = string_sprintf("%s/%s", pname, fname);
else if (!pname)
  mime_decoded_filename = string_copy(fname);
else if (!fname)
  {
  int file_nr = 0;
  int result = 0;

  /* must find first free sequential filename */
  do
    {
    struct stat mystat;
    mime_decoded_filename = string_sprintf("%s/%s-%05u", pname, message_id, file_nr++);
    /* security break */
    if (file_nr >= 1024)
      break;
    result = stat(CS mime_decoded_filename, &mystat);
    } while(result != -1);
  }

return modefopen(mime_decoded_filename, "wb+", SPOOL_MODE);
}


int
mime_decode(const uschar **listptr)
{
int sep = 0;
const uschar *list = *listptr;
uschar * option;
uschar * decode_path;
FILE *decode_file = NULL;
long f_pos = 0;
ssize_t size_counter = 0;
ssize_t (*decode_function)(FILE*, FILE*, uschar*);

if (!mime_stream || (f_pos = ftell(mime_stream)) < 0)
  return FAIL;

/* build default decode path (will exist since MBOX must be spooled up) */
decode_path = string_sprintf("%s/scan/%s", spool_directory, message_id);

/* try to find 1st option */
if ((option = string_nextinlist(&list, &sep, NULL, 0)))
  {
  /* parse 1st option */
  if ((Ustrcmp(option,"false") == 0) || (Ustrcmp(option,"0") == 0))
    /* explicitly no decoding */
    return FAIL;

  if (Ustrcmp(option,"default") == 0)
    /* explicit default path + file names */
    goto DEFAULT_PATH;

  if (option[0] == '/')
    {
    struct stat statbuf;

    memset(&statbuf,0,sizeof(statbuf));

    /* assume either path or path+file name */
    if ( (stat(CS option, &statbuf) == 0) && S_ISDIR(statbuf.st_mode) )
      /* is directory, use it as decode_path */
      decode_file = mime_get_decode_file(option, NULL);
    else
      /* does not exist or is a file, use as full file name */
      decode_file = mime_get_decode_file(NULL, option);
    }
  else
    /* assume file name only, use default path */
    decode_file = mime_get_decode_file(decode_path, option);
  }
else
  {
  /* no option? patch default path */
DEFAULT_PATH:
  decode_file = mime_get_decode_file(decode_path, NULL);
  }

if (!decode_file)
  return DEFER;

/* decode according to mime type */
decode_function =
  !mime_content_transfer_encoding
  ? mime_decode_asis	/* no encoding, dump as-is */
  : Ustrcmp(mime_content_transfer_encoding, "base64") == 0
  ? mime_decode_base64
  : Ustrcmp(mime_content_transfer_encoding, "quoted-printable") == 0
  ? mime_decode_qp
  : mime_decode_asis;	/* unknown encoding type, just dump as-is */

size_counter = decode_function(mime_stream, decode_file, mime_current_boundary);

clearerr(mime_stream);
if (fseek(mime_stream, f_pos, SEEK_SET))
  return DEFER;

if (fclose(decode_file) != 0 || size_counter < 0)
  return DEFER;

/* round up to the next KiB */
mime_content_size = (size_counter + 1023) / 1024;

return OK;
}


static int
mime_get_header(FILE *f, uschar *header)
{
int c = EOF;
int done = 0;
int header_value_mode = 0;
int header_open_brackets = 0;
int num_copied = 0;

while(!done)
  {
  if ((c = fgetc(f)) == EOF) break;

  /* always skip CRs */
  if (c == '\r') continue;

  if (c == '\n')
    {
    if (num_copied > 0)
      {
      /* look if next char is '\t' or ' ' */
      if ((c = fgetc(f)) == EOF) break;
      if ( (c == '\t') || (c == ' ') ) continue;
      (void)ungetc(c,f);
      }
    /* end of the header, terminate with ';' */
    c = ';';
    done = 1;
    }

  /* skip control characters */
  if (c < 32) continue;

  if (header_value_mode)
    {
    /* --------- value mode ----------- */
    /* skip leading whitespace */
    if ( ((c == '\t') || (c == ' ')) && (header_value_mode == 1) )
      continue;

    /* we have hit a non-whitespace char, start copying value data */
    header_value_mode = 2;

    if (c == '"')       /* flip "quoted" mode */
      header_value_mode = header_value_mode==2 ? 3 : 2;

    /* leave value mode on unquoted ';' */
    if (header_value_mode == 2 && c == ';')
      header_value_mode = 0;
    /* -------------------------------- */
    }
  else
    {
    /* -------- non-value mode -------- */
    /* skip whitespace + tabs */
    if ( (c == ' ') || (c == '\t') )
      continue;
    if (c == '\\')
      {
      /* quote next char. can be used
      to escape brackets. */
      if ((c = fgetc(f)) == EOF) break;
      }
    else if (c == '(')
      {
      header_open_brackets++;
      continue;
      }
    else if ((c == ')') && header_open_brackets)
      {
      header_open_brackets--;
      continue;
      }
    else if ( (c == '=') && !header_open_brackets ) /* enter value mode */
      header_value_mode = 1;

    /* skip chars while we are in a comment */
    if (header_open_brackets > 0)
      continue;
    /* -------------------------------- */
    }

  /* copy the char to the buffer */
  header[num_copied++] = (uschar)c;

  /* break if header buffer is full */
  if (num_copied > MIME_MAX_HEADER_SIZE-1)
    done = 1;
  }

if ((num_copied > 0) && (header[num_copied-1] != ';'))
  header[num_copied-1] = ';';

/* 0-terminate */
header[num_copied] = '\0';

/* return 0 for EOF or empty line */
if ((c == EOF) || (num_copied == 1))
  return 0;
else
  return 1;
}


static void
mime_vars_reset(void)
{
mime_anomaly_level     = 0;
mime_anomaly_text      = NULL;
mime_boundary          = NULL;
mime_charset           = NULL;
mime_decoded_filename  = NULL;
mime_filename          = NULL;
mime_content_description = NULL;
mime_content_disposition = NULL;
mime_content_id        = NULL;
mime_content_transfer_encoding = NULL;
mime_content_type      = NULL;
mime_is_multipart      = 0;
mime_content_size      = 0;
}


/* Grab a parameter value, dealing with quoting.

Arguments:
 str	Input string.  Updated on return to point to terminating ; or NUL

Return:
 Allocated string with parameter value
*/
static uschar *
mime_param_val(uschar ** sp)
{
uschar * s = *sp;
gstring * val = NULL;

/* debug_printf_indent("   considering paramval '%s'\n", s); */

while (*s && *s != ';')		/* ; terminates */
  if (*s == '"')
    {
    s++;			/* skip opening " */
    while (*s && *s != '"')	/* " protects ; */
      val = string_catn(val, s++, 1);
    if (*s) s++;		/* skip closing " */
    }
  else
    val = string_catn(val, s++, 1);
*sp = s;
return string_from_gstring(val);
}

static uschar *
mime_next_semicolon(uschar * s)
{
while (*s && *s != ';')		/* ; terminates */
  if (*s == '"')
    {
    s++;			/* skip opening " */
    while (*s && *s != '"')	/* " protects ; */
      s++;
    if (*s) s++;		/* skip closing " */
    }
  else
    s++;
return s;
}


static uschar *
rfc2231_to_2047(const uschar * fname, const uschar * charset, int * len)
{
gstring * val = string_catn(NULL, US"=?", 2);
uschar c;

if (charset)
  val = string_cat(val, charset);
val = string_catn(val, US"?Q?", 3);

while ((c = *fname))
  if (c == '%' && isxdigit(fname[1]) && isxdigit(fname[2]))
    {
    val = string_catn(val, US"=", 1);
    val = string_catn(val, ++fname, 2);
    fname += 2;
    }
  else
    val = string_catn(val, fname++, 1);

val = string_catn(val, US"?=", 2);
*len = val->ptr;
return string_from_gstring(val);
}


int
mime_acl_check(uschar *acl, FILE *f, struct mime_boundary_context *context,
    uschar **user_msgptr, uschar **log_msgptr)
{
int rc = OK;
uschar * header = NULL;
struct mime_boundary_context nested_context;

/* reserve a line buffer to work in */
header = store_get(MIME_MAX_HEADER_SIZE+1);

/* Not actually used at the moment, but will be vital to fixing
 * some RFC 2046 nonconformance later... */
nested_context.parent = context;

/* loop through parts */
while(1)
  {
  /* reset all per-part mime variables */
  mime_vars_reset();

  /* If boundary is null, we assume that *f is positioned on the start of
  headers (for example, at the very beginning of a message.  If a boundary is
  given, we must first advance to it to reach the start of the next header
  block.  */

  /* NOTE -- there's an error here -- RFC2046 specifically says to
   * check for outer boundaries.  This code doesn't do that, and
   * I haven't fixed this.
   *
   * (I have moved partway towards adding support, however, by adding
   * a "parent" field to my new boundary-context structure.)
   */
  if (context) for (;;)
    {
    if (!fgets(CS header, MIME_MAX_HEADER_SIZE, f))
      {
      /* Hit EOF or read error. Ugh. */
      DEBUG(D_acl) debug_printf_indent("MIME: Hit EOF ...\n");
      return rc;
      }

    /* boundary line must start with 2 dashes */
    if (  Ustrncmp(header, "--", 2) == 0
       && Ustrncmp(header+2, context->boundary, Ustrlen(context->boundary)) == 0
       )
      {			/* found boundary */
      if (Ustrncmp((header+2+Ustrlen(context->boundary)), "--", 2) == 0)
	{
	/* END boundary found */
	DEBUG(D_acl) debug_printf_indent("MIME: End boundary found %s\n",
	  context->boundary);
	return rc;
	}

      DEBUG(D_acl) debug_printf_indent("MIME: Next part with boundary %s\n",
	context->boundary);
      break;
      }
    }

  /* parse headers, set up expansion variables */
  while (mime_get_header(f, header))
    {
    struct mime_header * mh;

    /* look for interesting headers */
    for (mh = mime_header_list;
	 mh < mime_header_list + mime_header_list_size;
	 mh++) if (strncmpic(mh->name, header, mh->namelen) == 0)
      {
      uschar * p = header + mh->namelen;
      uschar * q;

      /* grab the value (normalize to lower case)
      and copy to its corresponding expansion variable */

      for (q = p; *q != ';' && *q; q++) ;
      *mh->value = string_copynlc(p, q-p);
      DEBUG(D_acl) debug_printf_indent("MIME: found %s header, value is '%s'\n",
	mh->name, *mh->value);

      if (*(p = q)) p++;			/* jump past the ; */

	{
	uschar * mime_fname = NULL;
	uschar * mime_fname_rfc2231 = NULL;
	uschar * mime_filename_charset = NULL;
	BOOL decoding_failed = FALSE;

	/* grab all param=value tags on the remaining line,
	check if they are interesting */

	while (*p)
	  {
	  mime_parameter * mp;

	  DEBUG(D_acl) debug_printf_indent("MIME:   considering paramlist '%s'\n", p);

	  if (  !mime_filename
	     && strncmpic(CUS"content-disposition:", header, 20) == 0
	     && strncmpic(CUS"filename*", p, 9) == 0
	     )
	    {					/* RFC 2231 filename */
	    uschar * q;

	    /* find value of the filename */
	    p += 9;
	    while(*p != '=' && *p) p++;
	    if (*p) p++;			/* p is filename or NUL */
	    q = mime_param_val(&p);		/* p now trailing ; or NUL */

	    if (q && *q)
	      {
	      uschar * temp_string, * err_msg;
	      int slen;

	      /* build up an un-decoded filename over successive
	      filename*= parameters (for use when 2047 decode fails) */

	      mime_fname_rfc2231 = string_sprintf("%#s%s",
		mime_fname_rfc2231, q);

	      if (!decoding_failed)
		{
		int size;
		if (!mime_filename_charset)
		  {
		  uschar * s = q;

		  /* look for a ' in the "filename" */
		  while(*s != '\'' && *s) s++;	/* s is 1st ' or NUL */

		  if ((size = s-q) > 0)
		    mime_filename_charset = string_copyn(q, size);

		  if (*(p = s)) p++;
		  while(*p == '\'') p++;	/* p is after 2nd ' */
		  }
		else
		  p = q;

		DEBUG(D_acl) debug_printf_indent("MIME:    charset %s fname '%s'\n",
		  mime_filename_charset ? mime_filename_charset : US"<NULL>", p);

		temp_string = rfc2231_to_2047(p, mime_filename_charset, &slen);
		DEBUG(D_acl) debug_printf_indent("MIME:    2047-name %s\n", temp_string);

		temp_string = rfc2047_decode(temp_string, FALSE, NULL, ' ',
		  NULL, &err_msg);
		DEBUG(D_acl) debug_printf_indent("MIME:    plain-name %s\n", temp_string);

		if (!temp_string || (size = Ustrlen(temp_string))  == slen)
		  decoding_failed = TRUE;
		else
		  /* build up a decoded filename over successive
		  filename*= parameters */

		  mime_filename = mime_fname = mime_fname
		    ? string_sprintf("%s%s", mime_fname, temp_string)
		    : temp_string;
		}
	      }
	    }

	  else
	    /* look for interesting parameters */
	    for (mp = mime_parameter_list;
		 mp < mime_parameter_list + nelem(mime_parameter_list);
		 mp++
		) if (strncmpic(mp->name, p, mp->namelen) == 0)
	      {
	      uschar * q;
	      uschar * dummy_errstr;

	      /* grab the value and copy to its expansion variable */
	      p += mp->namelen;
	      q = mime_param_val(&p);		/* p now trailing ; or NUL */

	      *mp->value = q && *q
		? rfc2047_decode(q, check_rfc2047_length, NULL, 32, NULL,
		    &dummy_errstr)
		: NULL;
	      DEBUG(D_acl) debug_printf_indent(
		"MIME:  found %s parameter in %s header, value '%s'\n",
		mp->name, mh->name, *mp->value);

	      break;			/* done matching param names */
	      }


	  /* There is something, but not one of our interesting parameters.
	     Advance past the next semicolon */
	  p = mime_next_semicolon(p);
	  if (*p) p++;
	  }				/* param scan on line */

	if (strncmpic(CUS"content-disposition:", header, 20) == 0)
	  {
	  if (decoding_failed) mime_filename = mime_fname_rfc2231;

	  DEBUG(D_acl) debug_printf_indent(
	    "MIME:  found %s parameter in %s header, value is '%s'\n",
	    "filename", mh->name, mime_filename);
	  }
	}
      }
    }

  /* set additional flag variables (easier access) */
  if (  mime_content_type
     && Ustrncmp(mime_content_type,"multipart",9) == 0
     )
    mime_is_multipart = 1;

  /* Make a copy of the boundary pointer.
     Required since mime_boundary is global
     and can be overwritten further down in recursion */
  nested_context.boundary = mime_boundary;

  /* raise global counter */
  mime_part_count++;

  /* copy current file handle to global variable */
  mime_stream = f;
  mime_current_boundary = context ? context->boundary : 0;

  /* Note the context */
  mime_is_coverletter = !(context && context->context == MBC_ATTACHMENT);

  /* call ACL handling function */
  rc = acl_check(ACL_WHERE_MIME, NULL, acl, user_msgptr, log_msgptr);

  mime_stream = NULL;
  mime_current_boundary = NULL;

  if (rc != OK) break;

  /* If we have a multipart entity and a boundary, go recursive */
  if ( (mime_content_type != NULL) &&
       (nested_context.boundary != NULL) &&
       (Ustrncmp(mime_content_type,"multipart",9) == 0) )
    {
    DEBUG(D_acl)
      debug_printf_indent("MIME: Entering multipart recursion, boundary '%s'\n",
	nested_context.boundary);

    nested_context.context =
      context && context->context == MBC_ATTACHMENT
      ? MBC_ATTACHMENT
      :    Ustrcmp(mime_content_type,"multipart/alternative") == 0
	|| Ustrcmp(mime_content_type,"multipart/related") == 0
      ? MBC_COVERLETTER_ALL
      : MBC_COVERLETTER_ONESHOT;

    rc = mime_acl_check(acl, f, &nested_context, user_msgptr, log_msgptr);
    if (rc != OK) break;
    }
  else if ( (mime_content_type != NULL) &&
	  (Ustrncmp(mime_content_type,"message/rfc822",14) == 0) )
    {
    const uschar *rfc822name = NULL;
    uschar filename[2048];
    int file_nr = 0;
    int result = 0;

    /* must find first free sequential filename */
    do
      {
      struct stat mystat;
      (void)string_format(filename, 2048,
	"%s/scan/%s/__rfc822_%05u", spool_directory, message_id, file_nr++);
      /* security break */
      if (file_nr >= 128)
	goto NO_RFC822;
      result = stat(CS filename,&mystat);
      } while (result != -1);

    rfc822name = filename;

    /* decode RFC822 attachment */
    mime_decoded_filename = NULL;
    mime_stream = f;
    mime_current_boundary = context ? context->boundary : NULL;
    mime_decode(&rfc822name);
    mime_stream = NULL;
    mime_current_boundary = NULL;
    if (!mime_decoded_filename)		/* decoding failed */
      {
      log_write(0, LOG_MAIN,
	   "MIME acl condition warning - could not decode RFC822 MIME part to file.");
      rc = DEFER;
      goto out;
      }
    mime_decoded_filename = NULL;
    }

NO_RFC822:
  /* If the boundary of this instance is NULL, we are finished here */
  if (!context) break;

  if (context->context == MBC_COVERLETTER_ONESHOT)
    context->context = MBC_ATTACHMENT;
  }

out:
mime_vars_reset();
return rc;
}

#endif	/*WITH_CONTENT_SCAN*/

/* vi: sw ai sw=2
*/
