/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


#include "exim.h"

static void (*oldsignal)(int);

#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_REQUIRETLS)
static uschar tls_requiretls_copy = 0;
#endif


/*************************************************
*          Ensure an fd has a given value        *
*************************************************/

/* This function is called when we want to ensure that a certain fd has a
specific value (one of 0, 1, 2). If it hasn't got it already, close the value
we want, duplicate the fd, then close the old one.

Arguments:
  oldfd        original fd
  newfd        the fd we want

Returns:       nothing
*/

static void
force_fd(int oldfd, int newfd)
{
if (oldfd == newfd) return;
(void)close(newfd);
(void)dup2(oldfd, newfd);
(void)close(oldfd);
}


#ifndef STAND_ALONE
/*************************************************
*   Build argv list and optionally re-exec Exim  *
*************************************************/

/* This function is called when Exim wants to re-exec (overlay) itself in the
current process. This is different to child_open_exim(), which runs another
Exim process in parallel (but it then calls this function). The function's
basic job is to build the argv list according to the values of current options
settings. There is a basic list that all calls require, and an additional list
that some do not require. Further additions can be given as additional
arguments. An option specifies whether the exec() is actually to happen, and if
so, what is to be done if it fails.

Arguments:
  exec_type      CEE_RETURN_ARGV => don't exec; return the argv list
                 CEE_EXEC_EXIT   => just exit() on exec failure
                 CEE_EXEC_PANIC  => panic-die on exec failure
  kill_v         if TRUE, don't pass on the D_v flag
  pcount         if not NULL, points to extra size of argv required, and if
                   CEE_RETURN_ARGV is specified, it is updated to give the
                   number of slots used
  minimal        TRUE if only minimal argv is required
  acount         number of additional arguments
  ...            further values to add to argv

Returns:         if CEE_RETURN_ARGV is given, returns a pointer to argv;
                 otherwise, does not return
*/

uschar **
child_exec_exim(int exec_type, BOOL kill_v, int *pcount, BOOL minimal,
  int acount, ...)
{
int first_special = -1;
int n = 0;
int extra = pcount ? *pcount : 0;
uschar **argv;

#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_REQUIRETLS)
if (tls_requiretls) extra++;
#endif

argv = store_get((extra + acount + MAX_CLMACROS + 18) * sizeof(char *));

/* In all case, the list starts out with the path, any macros, and a changed
config file. */

argv[n++] = exim_path;
if (clmacro_count > 0)
  {
  memcpy(argv + n, clmacros, clmacro_count * sizeof(uschar *));
  n += clmacro_count;
  }
if (f.config_changed)
  {
  argv[n++] = US"-C";
  argv[n++] = config_main_filename;
  }

/* These values are added only for non-minimal cases. If debug_selector is
precisely D_v, we have to assume this was started by a non-admin user, and
we suppress the flag when requested. (This happens when passing on an SMTP
connection, and after ETRN.) If there's more debugging going on, an admin user
was involved, so we do pass it on. */

if (!minimal)
  {
  if (debug_selector == D_v)
    {
    if (!kill_v) argv[n++] = US"-v";
    }
  else
    {
    if (debug_selector != 0)
      argv[n++] = string_sprintf("-d=0x%x", debug_selector);
    }
  if (f.dont_deliver) argv[n++] = US"-N";
  if (f.queue_smtp) argv[n++] = US"-odqs";
  if (f.synchronous_delivery) argv[n++] = US"-odi";
  if (connection_max_messages >= 0)
    argv[n++] = string_sprintf("-oB%d", connection_max_messages);
  if (*queue_name)
    {
    argv[n++] = US"-MCG";
    argv[n++] = queue_name;
    }
  }

#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_REQUIRETLS)
if (tls_requiretls_copy & REQUIRETLS_MSG)
  argv[n++] = US"-MS";
#endif

/* Now add in any others that are in the call. Remember which they were,
for more helpful diagnosis on failure. */

if (acount > 0)
  {
  va_list ap;
  va_start(ap, acount);
  first_special = n;
  while (acount-- > 0)
    argv[n++] = va_arg(ap, uschar *);
  va_end(ap);
  }

/* Terminate the list, and return it, if that is what is wanted. */

argv[n] = NULL;
if (exec_type == CEE_RETURN_ARGV)
  {
  if (pcount != NULL) *pcount = n;
  return argv;
  }

/* Otherwise, do the exec() here, and handle the consequences of an unexpected
failure. We know that there will always be at least one extra option in the
call when exec() is done here, so it can be used to add to the panic data. */

DEBUG(D_exec) debug_print_argv(CUSS argv);
exim_nullstd();                            /* Make sure std{in,out,err} exist */
execv(CS argv[0], (char *const *)argv);

log_write(0,
  LOG_MAIN | ((exec_type == CEE_EXEC_EXIT)? LOG_PANIC : LOG_PANIC_DIE),
  "re-exec of exim (%s) with %s failed: %s", exim_path, argv[first_special],
  strerror(errno));

/* Get here if exec_type == CEE_EXEC_EXIT.
Note: this must be _exit(), not exit(). */

_exit(EX_EXECFAILED);

return NULL;   /* To keep compilers happy */
}




/*************************************************
*          Create a child Exim process           *
*************************************************/

/* This function is called when Exim wants to run a parallel instance of itself
in order to inject a message via the standard input. The function creates a
child process and runs Exim in it. It sets up a pipe to the standard input of
the new process, and returns that to the caller via fdptr. The function returns
the pid of the new process, or -1 if things go wrong. If debug_fd is
non-negative, it is passed as stderr.

This interface is now a just wrapper for the more complicated function
child_open_exim2(), which has additional arguments. The wrapper must continue
to exist, even if all calls from within Exim are changed, because it is
documented for use from local_scan().

Argument: fdptr   pointer to int for the stdin fd
Returns:          pid of the created process or -1 if anything has gone wrong
*/

pid_t
child_open_exim(int *fdptr)
{
return child_open_exim2(fdptr, US"<>", bounce_sender_authentication);
}


/* This is a more complicated function for creating a child Exim process, with
more arguments.

Arguments:
  fdptr                   pointer to int for the stdin fd
  sender                  for a sender address (data for -f)
  sender_authentication   authenticated sender address or NULL

Returns:          pid of the created process or -1 if anything has gone wrong
*/

pid_t
child_open_exim2(int *fdptr, uschar *sender, uschar *sender_authentication)
{
int pfd[2];
int save_errno;
pid_t pid;

/* Create the pipe and fork the process. Ensure that SIGCHLD is set to
SIG_DFL before forking, so that the child process can be waited for. We
sometimes get here with it set otherwise. Save the old state for resetting
on the wait. */

if (pipe(pfd) != 0) return (pid_t)(-1);
oldsignal = signal(SIGCHLD, SIG_DFL);
pid = fork();

/* Child process: make the reading end of the pipe into the standard input and
close the writing end. If debugging, pass debug_fd as stderr. Then re-exec
Exim with appropriate options. In the test harness, use -odi unless queue_only
is set, so that the bounce is fully delivered before returning. Failure is
signalled with EX_EXECFAILED (specified by CEE_EXEC_EXIT), but this shouldn't
occur. */

if (pid == 0)
  {
#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_REQUIRETLS)
  tls_requiretls_copy = tls_requiretls;
#endif
  force_fd(pfd[pipe_read], 0);
  (void)close(pfd[pipe_write]);
  if (debug_fd > 0) force_fd(debug_fd, 2);
  if (f.running_in_test_harness && !queue_only)
    {
    if (sender_authentication != NULL)
      child_exec_exim(CEE_EXEC_EXIT, FALSE, NULL, FALSE, 9,
        US "-odi", US"-t", US"-oem", US"-oi", US"-f", sender, US"-oMas",
        sender_authentication, message_id_option);
    else
      child_exec_exim(CEE_EXEC_EXIT, FALSE, NULL, FALSE, 7,
        US "-odi", US"-t", US"-oem", US"-oi", US"-f", sender,
        message_id_option);
    /* Control does not return here. */
    }
  else   /* Not test harness */
    {
    if (sender_authentication != NULL)
      child_exec_exim(CEE_EXEC_EXIT, FALSE, NULL, FALSE, 8,
        US"-t", US"-oem", US"-oi", US"-f", sender, US"-oMas",
        sender_authentication, message_id_option);
    else
      child_exec_exim(CEE_EXEC_EXIT, FALSE, NULL, FALSE, 6,
        US"-t", US"-oem", US"-oi", US"-f", sender, message_id_option);
    /* Control does not return here. */
    }
  }

/* Parent process. Save fork() errno and close the reading end of the stdin
pipe. */

save_errno = errno;
(void)close(pfd[pipe_read]);

/* Fork succeeded */

if (pid > 0)
  {
  *fdptr = pfd[pipe_write];   /* return writing end of stdin pipe */
  return pid;                 /* and pid of new process */
  }

/* Fork failed */

(void)close(pfd[pipe_write]);
errno = save_errno;
return (pid_t)(-1);
}
#endif   /* STAND_ALONE */



/*************************************************
*         Create a non-Exim child process        *
*************************************************/

/* This function creates a child process and runs the given command in it. It
sets up pipes to the standard input and output of the new process, and returns
them to the caller. The standard error is cloned to the output. If there are
any file descriptors "in the way" in the new process, they are closed. A new
umask is supplied for the process, and an optional new uid and gid are also
available. These are used by the queryprogram router to set an unprivileged id.
SIGUSR1 is always disabled in the new process, as it is not going to be running
Exim (the function child_open_exim() is provided for that). This function
returns the pid of the new process, or -1 if things go wrong.

Arguments:
  argv        the argv for exec in the new process
  envp        the envp for exec in the new process
  newumask    umask to set in the new process
  newuid      point to uid for the new process or NULL for no change
  newgid      point to gid for the new process or NULL for no change
  infdptr     pointer to int into which the fd of the stdin of the new process
                is placed
  outfdptr    pointer to int into which the fd of the stdout/stderr of the new
                process is placed
  wd          if not NULL, a path to be handed to chdir() in the new process
  make_leader if TRUE, make the new process a process group leader

Returns:      the pid of the created process or -1 if anything has gone wrong
*/

pid_t
child_open_uid(const uschar **argv, const uschar **envp, int newumask,
  uid_t *newuid, gid_t *newgid, int *infdptr, int *outfdptr, uschar *wd,
  BOOL make_leader)
{
int save_errno;
int inpfd[2], outpfd[2];
pid_t pid;

/* Create the pipes. */

if (pipe(inpfd) != 0) return (pid_t)(-1);
if (pipe(outpfd) != 0)
  {
  (void)close(inpfd[pipe_read]);
  (void)close(inpfd[pipe_write]);
  return (pid_t)(-1);
  }

/* Fork the process. Ensure that SIGCHLD is set to SIG_DFL before forking, so
that the child process can be waited for. We sometimes get here with it set
otherwise. Save the old state for resetting on the wait. */

oldsignal = signal(SIGCHLD, SIG_DFL);
pid = fork();

/* Handle the child process. First, set the required environment. We must do
this before messing with the pipes, in order to be able to write debugging
output when things go wrong. */

if (pid == 0)
  {
  signal(SIGUSR1, SIG_IGN);
  signal(SIGPIPE, SIG_DFL);

  if (newgid != NULL && setgid(*newgid) < 0)
    {
    DEBUG(D_any) debug_printf("failed to set gid=%ld in subprocess: %s\n",
      (long int)(*newgid), strerror(errno));
    goto CHILD_FAILED;
    }

  if (newuid != NULL && setuid(*newuid) < 0)
    {
    DEBUG(D_any) debug_printf("failed to set uid=%ld in subprocess: %s\n",
      (long int)(*newuid), strerror(errno));
    goto CHILD_FAILED;
    }

  (void)umask(newumask);

  if (wd != NULL && Uchdir(wd) < 0)
    {
    DEBUG(D_any) debug_printf("failed to chdir to %s: %s\n", wd,
      strerror(errno));
    goto CHILD_FAILED;
    }

  /* Becomes a process group leader if requested, and then organize the pipes.
  Any unexpected failure is signalled with EX_EXECFAILED; these are all "should
  never occur" failures, except for exec failing because the command doesn't
  exist. */

  if (make_leader && setpgid(0,0) < 0)
    {
    DEBUG(D_any) debug_printf("failed to set group leader in subprocess: %s\n",
      strerror(errno));
    goto CHILD_FAILED;
    }

  (void)close(inpfd[pipe_write]);
  force_fd(inpfd[pipe_read], 0);

  (void)close(outpfd[pipe_read]);
  force_fd(outpfd[pipe_write], 1);

  (void)close(2);
  (void)dup2(1, 2);

  /* Now do the exec */

  if (envp == NULL) execv(CS argv[0], (char *const *)argv);
  else execve(CS argv[0], (char *const *)argv, (char *const *)envp);

  /* Failed to execv. Signal this failure using EX_EXECFAILED. We are
  losing the actual errno we got back, because there is no way to return
  this information. */

  CHILD_FAILED:
  _exit(EX_EXECFAILED);      /* Note: must be _exit(), NOT exit() */
  }

/* Parent process. Save any fork failure code, and close the reading end of the
stdin pipe, and the writing end of the stdout pipe. */

save_errno = errno;
(void)close(inpfd[pipe_read]);
(void)close(outpfd[pipe_write]);

/* Fork succeeded; return the input/output pipes and the pid */

if (pid > 0)
  {
  *infdptr = inpfd[pipe_write];
  *outfdptr = outpfd[pipe_read];
  return pid;
  }

/* Fork failed; reset fork errno before returning */

(void)close(inpfd[pipe_write]);
(void)close(outpfd[pipe_read]);
errno = save_errno;
return (pid_t)(-1);
}




/*************************************************
*    Create child process without uid change     *
*************************************************/

/* This function is a wrapper for child_open_uid() that doesn't have the uid,
gid and working directory changing arguments. The function is provided so as to
have a clean interface for use from local_scan(), but also saves writing NULL
arguments several calls that would otherwise use child_open_uid().

Arguments:
  argv        the argv for exec in the new process
  envp        the envp for exec in the new process
  newumask    umask to set in the new process
  infdptr     pointer to int into which the fd of the stdin of the new process
                is placed
  outfdptr    pointer to int into which the fd of the stdout/stderr of the new
                process is placed
  make_leader if TRUE, make the new process a process group leader

Returns:      the pid of the created process or -1 if anything has gone wrong
*/

pid_t
child_open(uschar **argv, uschar **envp, int newumask, int *infdptr,
  int *outfdptr, BOOL make_leader)
{
return child_open_uid(CUSS argv, CUSS envp, newumask, NULL, NULL,
  infdptr, outfdptr, NULL, make_leader);
}




/*************************************************
*           Close down child process             *
*************************************************/

/* Wait for the given process to finish, with optional timeout.

Arguments
  pid:      the pid to wait for
  timeout:  maximum time to wait; 0 means for as long as it takes

Returns:    >= 0          process terminated by exiting; value is process
                            ending status; if an execve() failed, the value
                            is typically 127 (defined as EX_EXECFAILED)
            < 0 & > -256  process was terminated by a signal; value is the
                            negation of the signal number
            -256          timed out
            -257          other error in wait(); errno still set
*/

int
child_close(pid_t pid, int timeout)
{
int yield;

if (timeout > 0)
  {
  sigalrm_seen = FALSE;
  ALARM(timeout);
  }

for(;;)
  {
  int status;
  pid_t rc = waitpid(pid, &status, 0);
  if (rc == pid)
    {
    int lowbyte = status & 255;
    yield = lowbyte == 0 ? (status >> 8) & 255 : -lowbyte;
    break;
    }
  if (rc < 0)
    {
    /* This "shouldn't happen" test does happen on MacOS: for some reason
    I do not understand we seems to get an alarm signal despite not having
    an active alarm set. There seems to be only one, so just go round again. */

    if (errno == EINTR && sigalrm_seen && timeout <= 0) continue;

    yield = (errno == EINTR && sigalrm_seen) ? -256 : -257;
    break;
    }
  }

if (timeout > 0) ALARM_CLR(0);

signal(SIGCHLD, oldsignal);   /* restore */
return yield;
}

/* End of child.c */
