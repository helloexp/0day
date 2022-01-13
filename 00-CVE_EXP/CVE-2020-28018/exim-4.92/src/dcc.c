/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Wolfgang Breyha 2005 - 2015
 * Vienna University Computer Center
 * wbreyha@gmx.net
 * See the file NOTICE for conditions of use and distribution.
 *
 * Copyright (c) The Exim Maintainers 2015 - 2018
 */

/* This patch is based on code from Tom Kistners exiscan (ACL integration) and
 * the DCC local_scan patch from Christopher Bodenstein */

/* Code for calling dccifd. Called from acl.c. */

#include "exim.h"
#ifdef EXPERIMENTAL_DCC
#include "dcc.h"
#include "unistd.h"

uschar dcc_header_str[256];
int dcc_ok = 0;
int dcc_rc = 0;

/* This function takes a file descriptor and a buffer as input and
 * returns either 0 for success or errno in case of error. */

int flushbuffer (int socket, uschar *buffer)
 {
  int retval, rsp;
  rsp = write(socket, buffer, Ustrlen(buffer));
  DEBUG(D_acl)
    debug_printf("DCC: Result of the write() = %d\n", rsp);
  if(rsp < 0)
  {
    DEBUG(D_acl)
      debug_printf("DCC: Error writing buffer to socket: %s\n", strerror(errno));
    retval = errno;
  }
  else {
    DEBUG(D_acl)
      debug_printf("DCC: Wrote buffer to socket:\n%s\n", buffer);
    retval = 0;
  }
  return retval;
}

int
dcc_process(uschar **listptr)
{
  int sep = 0;
  const uschar *list = *listptr;
  FILE *data_file;
  uschar *dcc_default_ip_option = US"127.0.0.1";
  uschar *dcc_helo_option = US"localhost";
  uschar *dcc_reject_message = US"Rejected by DCC";
  uschar *xtra_hdrs = NULL;
  uschar *override_client_ip  = NULL;

  /* from local_scan */
  int i, j, k, c, retval, sockfd, resp, line;
  unsigned int portnr;
  struct sockaddr_un  serv_addr;
  struct sockaddr_in  serv_addr_in;
  struct hostent *ipaddress;
  uschar sockpath[128];
  uschar sockip[40], client_ip[40];
  uschar opts[128];
  uschar rcpt[128], from[128];
  uschar sendbuf[4096];
  uschar recvbuf[4096];
  uschar dcc_return_text[1024];
  uschar message_subdir[2];
  struct header_line *dcchdr;
  uschar *dcc_acl_options;
  uschar dcc_acl_options_buffer[10];
  uschar dcc_xtra_hdrs[1024];

  /* grep 1st option */
  if ((dcc_acl_options = string_nextinlist(&list, &sep,
		   dcc_acl_options_buffer, sizeof(dcc_acl_options_buffer))))
    {
    /* parse 1st option */
    if (  strcmpic(dcc_acl_options, US"false") == 0
       || Ustrcmp(dcc_acl_options, "0") == 0
       )
      return FAIL;	/* explicitly no matching */
    }
  else
    return FAIL;	/* empty means "don't match anything" */

  sep = 0;

  /* if we scanned this message last time, just return */
  if (dcc_ok)
    return dcc_rc;

  /* open the spooled body */
  message_subdir[1] = '\0';
  for (i = 0; i < 2; i++)
    {
    message_subdir[0] = split_spool_directory == (i == 0) ? message_id[5] : 0;

    if ((data_file = Ufopen(
	    spool_fname(US"input", message_subdir, message_id, US"-D"),
	    "rb")))
      break;
    }

  if (!data_file)
    {
    /* error while spooling */
    log_write(0, LOG_MAIN|LOG_PANIC,
           "dcc acl condition: error while opening spool file");
    return DEFER;
    }

  /* Initialize the variables */

  bzero(sockip,sizeof(sockip));
  if (dccifd_address) {
    if (dccifd_address[0] == '/')
      Ustrncpy(sockpath, dccifd_address, sizeof(sockpath));
    else
      if( sscanf(CS dccifd_address, "%s %u", sockip, &portnr) != 2) {
        log_write(0, LOG_MAIN,
          "dcc acl condition: warning - invalid dccifd address: '%s'", dccifd_address);
        (void)fclose(data_file);
        return DEFER;
      }
  }

  /* opts is what we send as dccifd options - see man dccifd */
  /* We don't support any other option than 'header' so just copy that */
  bzero(opts,sizeof(opts));
  Ustrncpy(opts, dccifd_options, sizeof(opts)-1);
  /* if $acl_m_dcc_override_client_ip is set use it */
  if (((override_client_ip = expand_string(US"$acl_m_dcc_override_client_ip")) != NULL) &&
       (override_client_ip[0] != '\0')) {
    Ustrncpy(client_ip, override_client_ip, sizeof(client_ip)-1);
    DEBUG(D_acl)
      debug_printf("DCC: Client IP (overridden): %s\n", client_ip);
  }
  else if(sender_host_address) {
  /* else if $sender_host_address is available use that? */
    Ustrncpy(client_ip, sender_host_address, sizeof(client_ip)-1);
    DEBUG(D_acl)
      debug_printf("DCC: Client IP (sender_host_address): %s\n", client_ip);
  }
  else {
    /* sender_host_address is NULL which means it comes from localhost */
    Ustrncpy(client_ip, dcc_default_ip_option, sizeof(client_ip)-1);
    DEBUG(D_acl)
      debug_printf("DCC: Client IP (default): %s\n", client_ip);
  }
  /* strncat(opts, my_request, strlen(my_request)); */
  Ustrcat(opts, "\n");
  Ustrncat(opts, client_ip, sizeof(opts)-Ustrlen(opts)-1);
  Ustrncat(opts, "\nHELO ", sizeof(opts)-Ustrlen(opts)-1);
  Ustrncat(opts, dcc_helo_option, sizeof(opts)-Ustrlen(opts)-2);
  Ustrcat(opts, "\n");

  /* initialize the other variables */
  dcchdr = header_list;
  /* we set the default return value to DEFER */
  retval = DEFER;

  bzero(sendbuf,sizeof(sendbuf));
  bzero(dcc_header_str,sizeof(dcc_header_str));
  bzero(rcpt,sizeof(rcpt));
  bzero(from,sizeof(from));

  /* send a null return path as "<>". */
  if (Ustrlen(sender_address) > 0)
    Ustrncpy(from, sender_address, sizeof(from));
  else
    Ustrncpy(from, "<>", sizeof(from));
  Ustrncat(from, "\n", sizeof(from)-Ustrlen(from)-1);

  /**************************************
   * Now creating the socket connection *
   **************************************/

  /* If sockip contains an ip, we use a tcp socket, otherwise a UNIX socket */
  if(Ustrcmp(sockip, "")){
    ipaddress = gethostbyname(CS sockip);
    bzero(CS  &serv_addr_in, sizeof(serv_addr_in));
    serv_addr_in.sin_family = AF_INET;
    bcopy(CS ipaddress->h_addr, CS &serv_addr_in.sin_addr.s_addr, ipaddress->h_length);
    serv_addr_in.sin_port = htons(portnr);
    if ((sockfd = socket(AF_INET, SOCK_STREAM,0)) < 0){
      DEBUG(D_acl)
        debug_printf("DCC: Creating TCP socket connection failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Creating TCP socket connection failed: %s\n", strerror(errno));
      /* if we cannot create the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
    /* Now connecting the socket (INET) */
    if (connect(sockfd, (struct sockaddr *)&serv_addr_in, sizeof(serv_addr_in)) < 0){
      DEBUG(D_acl)
        debug_printf("DCC: Connecting to TCP socket failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Connecting to TCP socket failed: %s\n", strerror(errno));
      /* if we cannot contact the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
  } else {
    /* connecting to the dccifd UNIX socket */
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    Ustrncpy(serv_addr.sun_path, sockpath, sizeof(serv_addr.sun_path));
    if ((sockfd = socket(AF_UNIX, SOCK_STREAM,0)) < 0){
      DEBUG(D_acl)
        debug_printf("DCC: Creating UNIX socket connection failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Creating UNIX socket connection failed: %s\n", strerror(errno));
      /* if we cannot create the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
    /* Now connecting the socket (UNIX) */
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
      DEBUG(D_acl)
                            debug_printf("DCC: Connecting to UNIX socket failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Connecting to UNIX socket failed: %s\n", strerror(errno));
      /* if we cannot contact the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
  }
  /* the socket is open, now send the options to dccifd*/
  DEBUG(D_acl)
    debug_printf("\nDCC: ---------------------------\nDCC: Socket opened; now sending input\nDCC: -----------------\n");
  /* First, fill in the input buffer */
  Ustrncpy(sendbuf, opts, sizeof(sendbuf));
  Ustrncat(sendbuf, from, sizeof(sendbuf)-Ustrlen(sendbuf)-1);

  DEBUG(D_acl)
  {
    debug_printf("DCC: opts = %s\nDCC: sender = %s\nDCC: rcpt count = %d\n", opts, from, recipients_count);
    debug_printf("DCC: Sending options:\nDCC: ****************************\n");
  }

  /* let's send each of the recipients to dccifd */
  for (i = 0; i < recipients_count; i++){
    DEBUG(D_acl)
      debug_printf("DCC: recipient = %s\n",recipients_list[i].address);
    if(Ustrlen(sendbuf) + Ustrlen(recipients_list[i].address) > sizeof(sendbuf))
    {
      DEBUG(D_acl)
        debug_printf("DCC: Writing buffer: %s\n", sendbuf);
      flushbuffer(sockfd, sendbuf);
      bzero(sendbuf, sizeof(sendbuf));
    }
    Ustrncat(sendbuf, recipients_list[i].address, sizeof(sendbuf)-Ustrlen(sendbuf)-1);
    Ustrncat(sendbuf, "\r\n", sizeof(sendbuf)-Ustrlen(sendbuf)-1);
  }
  /* send a blank line between options and message */
  Ustrncat(sendbuf, "\n", sizeof(sendbuf)-Ustrlen(sendbuf)-1);
  /* Now we send the input buffer */
  DEBUG(D_acl)
    debug_printf("DCC: %s\nDCC: ****************************\n", sendbuf);
  flushbuffer(sockfd, sendbuf);

  /* now send the message */
  /* Clear the input buffer */
  bzero(sendbuf, sizeof(sendbuf));
  /* First send the headers */
  /* Now send the headers */
  DEBUG(D_acl)
    debug_printf("DCC: Sending headers:\nDCC: ****************************\n");
  Ustrncpy(sendbuf, dcchdr->text, sizeof(sendbuf)-2);
  while((dcchdr=dcchdr->next)) {
    if(dcchdr->slen > sizeof(sendbuf)-2) {
      /* The size of the header is bigger than the size of
       * the input buffer, so split it up in smaller parts. */
       flushbuffer(sockfd, sendbuf);
       bzero(sendbuf, sizeof(sendbuf));
       j = 0;
       while(j < dcchdr->slen)
       {
        for(i = 0; i < sizeof(sendbuf)-2; i++) {
          sendbuf[i] = dcchdr->text[j];
          j++;
        }
        flushbuffer(sockfd, sendbuf);
        bzero(sendbuf, sizeof(sendbuf));
       }
    } else if(Ustrlen(sendbuf) + dcchdr->slen > sizeof(sendbuf)-2) {
      flushbuffer(sockfd, sendbuf);
      bzero(sendbuf, sizeof(sendbuf));
      Ustrncpy(sendbuf, dcchdr->text, sizeof(sendbuf)-2);
    } else {
      Ustrncat(sendbuf, dcchdr->text, sizeof(sendbuf)-Ustrlen(sendbuf)-2);
    }
  }

  /* a blank line separates header from body */
  Ustrncat(sendbuf, "\n", sizeof(sendbuf)-Ustrlen(sendbuf)-1);
  flushbuffer(sockfd, sendbuf);
  DEBUG(D_acl)
    debug_printf("\nDCC: ****************************\n%s", sendbuf);

  /* Clear the input buffer */
  bzero(sendbuf, sizeof(sendbuf));

  /* now send the body */
  DEBUG(D_acl)
    debug_printf("DCC: Writing body:\nDCC: ****************************\n");
  (void)fseek(data_file, SPOOL_DATA_START_OFFSET, SEEK_SET);
  while((fread(sendbuf, 1, sizeof(sendbuf)-1, data_file)) > 0) {
    flushbuffer(sockfd, sendbuf);
    bzero(sendbuf, sizeof(sendbuf));
  }
  DEBUG(D_acl)
    debug_printf("\nDCC: ****************************\n");

  /* shutdown() the socket */
  if(shutdown(sockfd, 1) < 0){
    DEBUG(D_acl)
      debug_printf("DCC: Couldn't shutdown socket: %s\n", strerror(errno));
    log_write(0,LOG_MAIN,"DCC: Couldn't shutdown socket: %s\n", strerror(errno));
    /* If there is a problem with the shutdown()
     * defer the mail. */
    (void)fclose(data_file);
    return retval;
  }
  DEBUG(D_acl)
    debug_printf("\nDCC: -------------------------\nDCC: Input sent.\nDCC: -------------------------\n");

    /********************************
   * receiving output from dccifd *
   ********************************/
  DEBUG(D_acl)
    debug_printf("\nDCC: -------------------------------------\nDCC: Now receiving output from server\nDCC: -----------------------------------\n");

  /******************************************************************
   * We should get 3 lines:                                         *
   * 1/ First line is overall result: either 'A' for Accept,        *
   *    'R' for Reject, 'S' for accept Some recipients or           *
   *    'T' for a Temporary error.                                  *
   * 2/ Second line contains the list of Accepted/Rejected          *
   *    recipients in the form AARRA (A = accepted, R = rejected).  *
   * 3/ Third line contains the X-DCC header.                       *
   ******************************************************************/

  line = 1;    /* we start at the first line of the output */
  j = 0;       /* will be used as index for the recipients list */
  k = 0;       /* initializing the index of the X-DCC header: dcc_header_str[k] */

  /* Let's read from the socket until there's nothing left to read */
  bzero(recvbuf, sizeof(recvbuf));
  while((resp = read(sockfd, recvbuf, sizeof(recvbuf)-1)) > 0) {
    /* How much did we get from the socket */
    c = Ustrlen(recvbuf) + 1;
    DEBUG(D_acl)
      debug_printf("DCC: Length of the output buffer is: %d\nDCC: Output buffer is:\nDCC: ------------\nDCC: %s\nDCC: -----------\n", c, recvbuf);

    /* Now let's read each character and see what we've got */
    for(i = 0; i < c; i++) {
      /* First check if we reached the end of the line and
       * then increment the line counter */
      if(recvbuf[i] == '\n') {
        line++;
      }
      else {
        /* The first character of the first line is the
         * overall response. If there's another character
         * on that line it is not correct. */
        if(line == 1) {
          if(i == 0) {
            /* Now get the value and set the
             * return value accordingly */
            if(recvbuf[i] == 'A') {
              DEBUG(D_acl)
                debug_printf("DCC: Overall result = A\treturning OK\n");
              Ustrcpy(dcc_return_text, "Mail accepted by DCC");
              dcc_result = US"A";
              retval = OK;
            }
            else if(recvbuf[i] == 'R') {
              DEBUG(D_acl)
                debug_printf("DCC: Overall result = R\treturning FAIL\n");
              dcc_result = US"R";
              retval = FAIL;
              if(sender_host_name) {
                log_write(0, LOG_MAIN, "H=%s [%s] F=<%s>: rejected by DCC", sender_host_name, sender_host_address, sender_address);
              }
              else {
                log_write(0, LOG_MAIN, "H=[%s] F=<%s>: rejected by DCC", sender_host_address, sender_address);
              }
              Ustrncpy(dcc_return_text, dcc_reject_message, Ustrlen(dcc_reject_message) + 1);
            }
            else if(recvbuf[i] == 'S') {
              DEBUG(D_acl)
                debug_printf("DCC: Overall result  = S\treturning OK\n");
              Ustrcpy(dcc_return_text, "Not all recipients accepted by DCC");
              /* Since we're in an ACL we want a global result
               * so we accept for all */
              dcc_result = US"A";
              retval = OK;
            }
            else if(recvbuf[i] == 'G') {
              DEBUG(D_acl)
                debug_printf("DCC: Overall result  = G\treturning FAIL\n");
              Ustrcpy(dcc_return_text, "Greylisted by DCC");
              dcc_result = US"G";
              retval = FAIL;
            }
            else if(recvbuf[i] == 'T') {
              DEBUG(D_acl)
                debug_printf("DCC: Overall result = T\treturning DEFER\n");
              retval = DEFER;
              log_write(0,LOG_MAIN,"Temporary error with DCC: %s\n", recvbuf);
              Ustrcpy(dcc_return_text, "Temporary error with DCC");
              dcc_result = US"T";
            }
            else {
              DEBUG(D_acl)
                debug_printf("DCC: Overall result = something else\treturning DEFER\n");
              retval = DEFER;
              log_write(0,LOG_MAIN,"Unknown DCC response: %s\n", recvbuf);
              Ustrcpy(dcc_return_text, "Unknown DCC response");
              dcc_result = US"T";
            }
          }
          else {
            /* We're on the first line but not on the first character,
             * there must be something wrong. */
            DEBUG(D_acl) debug_printf("DCC: Line = %d but i = %d != 0"
		"  character is %c - This is wrong!\n", line, i, recvbuf[i]);
            log_write(0,LOG_MAIN,"Wrong header from DCC, output is %s\n", recvbuf);
          }
        }
        else if(line == 2) {
          /* On the second line we get a list of
           * answers for each recipient. We don't care about
           * it because we're in an acl and take the
           * global result. */
        }
        else if(line > 2) {
          /* The third and following lines are the X-DCC header,
           * so we store it in dcc_header_str. */
          /* check if we don't get more than we can handle */
          if(k < sizeof(dcc_header_str)) {
            dcc_header_str[k] = recvbuf[i];
            k++;
          }
          else {
            DEBUG(D_acl) debug_printf("DCC: We got more output than we can store"
		" in the X-DCC header. Truncating at 120 characters.\n");
          }
        }
        else {
          /* Wrong line number. There must be a problem with the output. */
          DEBUG(D_acl)
            debug_printf("DCC: Wrong line number in output. Line number is %d\n", line);
        }
      }
    }
    /* we reinitialize the output buffer before we read again */
    bzero(recvbuf,sizeof(recvbuf));
  }
  /* We have read everything from the socket */

  /* We need to terminate the X-DCC header with a '\n' character. This needs to be k-1
   * since dcc_header_str[k] contains '\0'. */
  dcc_header_str[k-1] = '\n';

  /* Now let's sum up what we've got. */
  DEBUG(D_acl)
    debug_printf("\nDCC: --------------------------\nDCC: Overall result = %d\nDCC: X-DCC header: %sReturn message: %s\nDCC: dcc_result: %s\n", retval, dcc_header_str, dcc_return_text, dcc_result);

  /* We only add the X-DCC header if it starts with X-DCC */
  if(!(Ustrncmp(dcc_header_str, "X-DCC", 5))){
    dcc_header = dcc_header_str;
    if(dcc_direct_add_header) {
      header_add(' ' , "%s", dcc_header_str);
  /* since the MIME ACL already writes the .eml file to disk without DCC Header we've to erase it */
      unspool_mbox();
    }
  }
  else {
    DEBUG(D_acl)
      debug_printf("DCC: Wrong format of the X-DCC header: %s\n", dcc_header_str);
  }

  /* check if we should add additional headers passed in acl_m_dcc_add_header */
  if(dcc_direct_add_header) {
    if (((xtra_hdrs = expand_string(US"$acl_m_dcc_add_header")) != NULL) && (xtra_hdrs[0] != '\0')) {
      Ustrncpy(dcc_xtra_hdrs, xtra_hdrs, sizeof(dcc_xtra_hdrs) - 2);
      if (dcc_xtra_hdrs[Ustrlen(dcc_xtra_hdrs)-1] != '\n')
        Ustrcat(dcc_xtra_hdrs, "\n");
      header_add(' ', "%s", dcc_xtra_hdrs);
      DEBUG(D_acl)
        debug_printf("DCC: adding additional headers in $acl_m_dcc_add_header: %s", dcc_xtra_hdrs);
    }
  }

  dcc_ok = 1;
  /* Now return to exim main process */
  DEBUG(D_acl)
    debug_printf("DCC: Before returning to exim main process:\nDCC: return_text = %s - retval = %d\nDCC: dcc_result = %s\n", dcc_return_text, retval, dcc_result);

  (void)fclose(data_file);
  dcc_rc = retval;
  return dcc_rc;
}

#endif
