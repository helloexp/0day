/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Code for calling Brightmail AntiSpam.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004
   License: GPL */

#include "exim.h"
#ifdef EXPERIMENTAL_BRIGHTMAIL

#include "bmi_spam.h"

uschar *bmi_current_optin = NULL;

uschar *bmi_process_message(header_line *header_list, int data_fd) {
  BmiSystem *system = NULL;
  BmiMessage *message = NULL;
  BmiError err;
  BmiErrorLocation err_loc;
  BmiErrorType err_type;
  const BmiVerdict *verdict = NULL;
  FILE *data_file;
  uschar data_buffer[4096];
  uschar localhost[] = "127.0.0.1";
  uschar *host_address;
  uschar *verdicts = NULL;
  int i,j;

  err = bmiInitSystem(BMI_VERSION, CS bmi_config_file, &system);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: could not initialize Brightmail system.", (int)err_loc, (int)err_type);
    return NULL;
  }

  err = bmiInitMessage(system, &message);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: could not initialize Brightmail message.", (int)err_loc, (int)err_type);
    bmiFreeSystem(system);
    return NULL;
  }

  /* Send IP address of sending host */
  if (sender_host_address == NULL)
    host_address = localhost;
  else
    host_address = sender_host_address;
  err = bmiProcessConnection(CS host_address, message);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiProcessConnection() failed (IP %s).", (int)err_loc, (int)err_type, CS host_address);
    bmiFreeMessage(message);
    bmiFreeSystem(system);
    return NULL;
  };

  /* Send envelope sender address */
  err = bmiProcessFROM(CS sender_address, message);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiProcessFROM() failed (address %s).", (int)err_loc, (int)err_type, CS sender_address);
    bmiFreeMessage(message);
    bmiFreeSystem(system);
    return NULL;
  };

  /* Send envelope recipients */
  for(i=0;i<recipients_count;i++) {
    recipient_item *r = recipients_list + i;
    BmiOptin *optin = NULL;

    /* create optin object if optin string is given */
    if ((r->bmi_optin != NULL) && (Ustrlen(r->bmi_optin) > 1)) {
      debug_printf("passing bmiOptin string: %s\n", r->bmi_optin);
      bmiOptinInit(&optin);
      err = bmiOptinMset(optin, r->bmi_optin, ':');
      if (bmiErrorIsFatal(err) == BMI_TRUE) {
        log_write(0, LOG_PANIC|LOG_MAIN,
                   "bmi warning: [loc %d type %d]: bmiOptinMSet() failed (address '%s', string '%s').", (int)err_loc, (int)err_type, CS r->address, CS r->bmi_optin);
        if (optin != NULL)
          bmiOptinFree(optin);
        optin = NULL;
      };
    };

    err = bmiAccumulateTO(CS r->address, optin, message);

    if (optin != NULL)
      bmiOptinFree(optin);

    if (bmiErrorIsFatal(err) == BMI_TRUE) {
      err_loc = bmiErrorGetLocation(err);
      err_type = bmiErrorGetType(err);
      log_write(0, LOG_PANIC,
                 "bmi error [loc %d type %d]: bmiAccumulateTO() failed (address %s).", (int)err_loc, (int)err_type, CS r->address);
      bmiFreeMessage(message);
      bmiFreeSystem(system);
      return NULL;
    };
  };
  err = bmiEndTO(message);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiEndTO() failed.", (int)err_loc, (int)err_type);
    bmiFreeMessage(message);
    bmiFreeSystem(system);
    return NULL;
  };

  /* Send message headers */
  while (header_list != NULL) {
    /* skip deleted headers */
    if (header_list->type == '*') {
      header_list = header_list->next;
      continue;
    };
    err = bmiAccumulateHeaders(CCS header_list->text, header_list->slen, message);
    if (bmiErrorIsFatal(err) == BMI_TRUE) {
      err_loc = bmiErrorGetLocation(err);
      err_type = bmiErrorGetType(err);
      log_write(0, LOG_PANIC,
                 "bmi error [loc %d type %d]: bmiAccumulateHeaders() failed.", (int)err_loc, (int)err_type);
      bmiFreeMessage(message);
      bmiFreeSystem(system);
      return NULL;
    };
    header_list = header_list->next;
  };
  err = bmiEndHeaders(message);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiEndHeaders() failed.", (int)err_loc, (int)err_type);
    bmiFreeMessage(message);
    bmiFreeSystem(system);
    return NULL;
  };

  /* Send body */
  data_file = fdopen(data_fd,"r");
  do {
    j = fread(data_buffer, 1, sizeof(data_buffer), data_file);
    if (j > 0) {
      err = bmiAccumulateBody(CCS data_buffer, j, message);
      if (bmiErrorIsFatal(err) == BMI_TRUE) {
        err_loc = bmiErrorGetLocation(err);
        err_type = bmiErrorGetType(err);
        log_write(0, LOG_PANIC,
                   "bmi error [loc %d type %d]: bmiAccumulateBody() failed.", (int)err_loc, (int)err_type);
        bmiFreeMessage(message);
        bmiFreeSystem(system);
        return NULL;
      };
    };
  } while (j > 0);
  err = bmiEndBody(message);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiEndBody() failed.", (int)err_loc, (int)err_type);
    bmiFreeMessage(message);
    bmiFreeSystem(system);
    return NULL;
  };


  /* End message */
  err = bmiEndMessage(message);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiEndMessage() failed.", (int)err_loc, (int)err_type);
    bmiFreeMessage(message);
    bmiFreeSystem(system);
    return NULL;
  };

  /* get store for the verdict string */
  verdicts = store_get(1);
  *verdicts = '\0';

  for ( err = bmiAccessFirstVerdict(message, &verdict);
        verdict != NULL;
        err = bmiAccessNextVerdict(message, verdict, &verdict) ) {
    char *verdict_str;

    err = bmiCreateStrFromVerdict(verdict,&verdict_str);
    if (!store_extend(verdicts, Ustrlen(verdicts)+1, Ustrlen(verdicts)+1+strlen(verdict_str)+1)) {
      /* can't allocate more store */
      return NULL;
    };
    if (*verdicts != '\0')
      Ustrcat(verdicts, US ":");
    Ustrcat(verdicts, US verdict_str);
    bmiFreeStr(verdict_str);
  };

  DEBUG(D_receive) debug_printf("bmi verdicts: %s\n", verdicts);

  if (Ustrlen(verdicts) == 0)
    return NULL;
  else
    return verdicts;
}


int bmi_get_delivery_status(uschar *base64_verdict) {
  BmiError err;
  BmiErrorLocation err_loc;
  BmiErrorType err_type;
  BmiVerdict *verdict = NULL;
  int rc = 1;   /* deliver by default */

  /* always deliver when there is no verdict */
  if (base64_verdict == NULL)
    return 1;

  /* create verdict from base64 string */
  err = bmiCreateVerdictFromStr(CS base64_verdict, &verdict);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiCreateVerdictFromStr() failed. [%s]", (int)err_loc, (int)err_type, base64_verdict);
    return 1;
  };

  err = bmiVerdictError(verdict);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    /* deliver normally due to error */
    rc = 1;
  }
  else if (bmiVerdictDestinationIsDefault(verdict) == BMI_TRUE) {
    /* deliver normally */
    rc = 1;
  }
  else if (bmiVerdictAccessDestination(verdict) == NULL) {
    /* do not deliver */
    rc = 0;
  }
  else {
    /* deliver to alternate location */
    rc = 1;
  };

  bmiFreeVerdict(verdict);
  return rc;
}


uschar *bmi_get_alt_location(uschar *base64_verdict) {
  BmiError err;
  BmiErrorLocation err_loc;
  BmiErrorType err_type;
  BmiVerdict *verdict = NULL;
  uschar *rc = NULL;

  /* always deliver when there is no verdict */
  if (base64_verdict == NULL)
    return NULL;

  /* create verdict from base64 string */
  err = bmiCreateVerdictFromStr(CS base64_verdict, &verdict);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiCreateVerdictFromStr() failed. [%s]", (int)err_loc, (int)err_type, base64_verdict);
    return NULL;
  };

  err = bmiVerdictError(verdict);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    /* deliver normally due to error */
    rc = NULL;
  }
  else if (bmiVerdictDestinationIsDefault(verdict) == BMI_TRUE) {
    /* deliver normally */
    rc = NULL;
  }
  else if (bmiVerdictAccessDestination(verdict) == NULL) {
    /* do not deliver */
    rc = NULL;
  }
  else {
    /* deliver to alternate location */
    rc = store_get(strlen(bmiVerdictAccessDestination(verdict))+1);
    Ustrcpy(rc, bmiVerdictAccessDestination(verdict));
    rc[strlen(bmiVerdictAccessDestination(verdict))] = '\0';
  };

  bmiFreeVerdict(verdict);
  return rc;
}

uschar *bmi_get_base64_verdict(uschar *bmi_local_part, uschar *bmi_domain) {
  BmiError err;
  BmiErrorLocation err_loc;
  BmiErrorType err_type;
  BmiVerdict *verdict = NULL;
  const BmiRecipient *recipient = NULL;
  const char *verdict_str = NULL;
  uschar *verdict_ptr;
  uschar *verdict_buffer = NULL;
  int sep = 0;

  /* return nothing if there are no verdicts available */
  if (bmi_verdicts == NULL)
    return NULL;

  /* allocate room for the b64 verdict string */
  verdict_buffer = store_get(Ustrlen(bmi_verdicts)+1);

  /* loop through verdicts */
  verdict_ptr = bmi_verdicts;
  while ((verdict_str = CCS string_nextinlist(&verdict_ptr, &sep,
                                          verdict_buffer,
                                          Ustrlen(bmi_verdicts)+1)) != NULL) {

    /* create verdict from base64 string */
    err = bmiCreateVerdictFromStr(verdict_str, &verdict);
    if (bmiErrorIsFatal(err) == BMI_TRUE) {
      err_loc = bmiErrorGetLocation(err);
      err_type = bmiErrorGetType(err);
      log_write(0, LOG_PANIC,
                 "bmi error [loc %d type %d]: bmiCreateVerdictFromStr() failed. [%s]", (int)err_loc, (int)err_type, verdict_str);
      return NULL;
    };

    /* loop through rcpts for this verdict */
    for ( recipient = bmiVerdictAccessFirstRecipient(verdict);
          recipient != NULL;
          recipient = bmiVerdictAccessNextRecipient(verdict, recipient)) {
      uschar *rcpt_local_part;
      uschar *rcpt_domain;

      /* compare address against our subject */
      rcpt_local_part = US bmiRecipientAccessAddress(recipient);
      rcpt_domain = Ustrchr(rcpt_local_part,'@');
      if (rcpt_domain == NULL) {
        rcpt_domain = US"";
      }
      else {
        *rcpt_domain = '\0';
        rcpt_domain++;
      };

      if ( (strcmpic(rcpt_local_part, bmi_local_part) == 0) &&
           (strcmpic(rcpt_domain, bmi_domain) == 0) ) {
        /* found verdict */
        bmiFreeVerdict(verdict);
        return US verdict_str;
      };
    };

    bmiFreeVerdict(verdict);
  };

  return NULL;
}


uschar *bmi_get_base64_tracker_verdict(uschar *base64_verdict) {
  BmiError err;
  BmiErrorLocation err_loc;
  BmiErrorType err_type;
  BmiVerdict *verdict = NULL;
  uschar *rc = NULL;

  /* always deliver when there is no verdict */
  if (base64_verdict == NULL)
    return NULL;

  /* create verdict from base64 string */
  err = bmiCreateVerdictFromStr(CS base64_verdict, &verdict);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiCreateVerdictFromStr() failed. [%s]", (int)err_loc, (int)err_type, base64_verdict);
    return NULL;
  };

  /* create old tracker string from verdict */
  err = bmiCreateOldStrFromVerdict(verdict, &rc);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiCreateOldStrFromVerdict() failed. [%s]", (int)err_loc, (int)err_type, base64_verdict);
    return NULL;
  };

  bmiFreeVerdict(verdict);
  return rc;
}


int bmi_check_rule(uschar *base64_verdict, uschar *option_list) {
  BmiError err;
  BmiErrorLocation err_loc;
  BmiErrorType err_type;
  BmiVerdict *verdict = NULL;
  int rc = 0;
  uschar *rule_num;
  uschar *rule_ptr;
  uschar rule_buffer[32];
  int sep = 0;


  /* no verdict -> no rule fired */
  if (base64_verdict == NULL)
    return 0;

  /* create verdict from base64 string */
  err = bmiCreateVerdictFromStr(CS base64_verdict, &verdict);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    err_loc = bmiErrorGetLocation(err);
    err_type = bmiErrorGetType(err);
    log_write(0, LOG_PANIC,
               "bmi error [loc %d type %d]: bmiCreateVerdictFromStr() failed. [%s]", (int)err_loc, (int)err_type, base64_verdict);
    return 0;
  };

  err = bmiVerdictError(verdict);
  if (bmiErrorIsFatal(err) == BMI_TRUE) {
    /* error -> no rule fired */
    bmiFreeVerdict(verdict);
    return 0;
  }

  /* loop through numbers */
  rule_ptr = option_list;
  while ((rule_num = string_nextinlist(&rule_ptr, &sep,
                                       rule_buffer, 32)) != NULL) {
    int rule_int = -1;

    /* try to translate to int */
    (void)sscanf(rule_num, "%d", &rule_int);
    if (rule_int > 0) {
      debug_printf("checking rule #%d\n", rule_int);
      /* check if rule fired on the message */
      if (bmiVerdictRuleFired(verdict, rule_int) == BMI_TRUE) {
        debug_printf("rule #%d fired\n", rule_int);
        rc = 1;
        break;
      };
    };
  };

  bmiFreeVerdict(verdict);
  return rc;
};

#endif
