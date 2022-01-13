/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#ifdef STAND_ALONE
# include <signal.h>
# include <stdio.h>
# include <time.h>
#endif

#ifndef CS
# define CS (char *)
# define US (unsigned char *)
#endif

/* This source file contains "default" system-dependent functions which
provide functionality (or lack of it) in cases where the OS-specific os.c
file has not. Some of them are tailored by macros defined in os.h files. */


#ifndef OS_RESTARTING_SIGNAL
/*************************************************
*          Set up restarting signal              *
*************************************************/

/* This function has the same functionality as the ANSI C signal() function,
except that it arranges that, if the signal happens during a system call, the
system call gets restarted. (Also, it doesn't return a result.) Different
versions of Unix have different defaults, and different ways of setting up a
restarting signal handler. If the functionality is not available, the signal
should be set to be ignored. This function is used only for catching SIGUSR1.
*/

void
os_restarting_signal(int sig, void (*handler)(int))
{
/* Many systems have the SA_RESTART sigaction for specifying that a signal
should restart system calls. These include SunOS5, AIX, BSDI, IRIX, FreeBSD,
OSF1, Linux and HP-UX 10 (but *not* HP-UX 9). */

#ifdef SA_RESTART
struct sigaction act;
act.sa_handler = handler;
sigemptyset(&(act.sa_mask));
act.sa_flags = SA_RESTART;
sigaction(sig, &act, NULL);

#ifdef STAND_ALONE
printf("Used SA_RESTART\n");
#endif

/* SunOS4 and Ultrix default to non-interruptable signals, with SV_INTERRUPT
for making them interruptable. This seems to be a dying fashion. */

#elif defined SV_INTERRUPT
signal(sig, handler);

#ifdef STAND_ALONE
printf("Used default signal()\n");
#endif


/* If neither SA_RESTART nor SV_INTERRUPT is available we don't know how to
set up a restarting signal, so simply suppress the facility. */

#else
signal(sig, SIG_IGN);

#ifdef STAND_ALONE
printf("Used SIG_IGN\n");
#endif

#endif
}

#endif  /* OS_RESTARTING_SIGNAL */


#ifndef OS_NON_RESTARTING_SIGNAL
/*************************************************
*          Set up non-restarting signal          *
*************************************************/

/* This function has the same functionality as the ANSI C signal() function,
except that it arranges that, if the signal happens during a system call, the
system call gets interrupted. (Also, it doesn't return a result.) Different
versions of Unix have different defaults, and different ways of setting up a
non-restarting signal handler. For systems for which we don't know what to do,
just use the normal signal() function and hope for the best. */

void
os_non_restarting_signal(int sig, void (*handler)(int))
{
/* Many systems have the SA_RESTART sigaction for specifying that a signal
should restart system calls. These include SunOS5, AIX, BSDI, IRIX, FreeBSD,
OSF1, Linux and HP-UX 10 (but *not* HP-UX 9). */

#ifdef SA_RESTART
struct sigaction act;
act.sa_handler = handler;
sigemptyset(&(act.sa_mask));
act.sa_flags = 0;
sigaction(sig, &act, NULL);

#ifdef STAND_ALONE
printf("Used sigaction() with flags = 0\n");
#endif

/* SunOS4 and Ultrix default to non-interruptable signals, with SV_INTERRUPT
for making them interruptable. This seems to be a dying fashion. */

#elif defined SV_INTERRUPT
struct sigvec sv;
sv.sv_handler = handler;
sv.sv_flags = SV_INTERRUPT;
sv.sv_mask = -1;
sigvec(sig, &sv, NULL);

#ifdef STAND_ALONE
printf("Used sigvec() with flags = SV_INTERRUPT\n");
#endif

/* If neither SA_RESTART nor SV_INTERRUPT is available we don't know how to
set up a restarting signal, so just use the standard signal() function. */

#else
signal(sig, handler);

#ifdef STAND_ALONE
printf("Used default signal()\n");
#endif

#endif
}

#endif  /* OS_NON_RESTARTING_SIGNAL */



#ifdef STRERROR_FROM_ERRLIST
/*************************************************
*     Provide strerror() for non-ANSI libraries  *
*************************************************/

/* Some old-fashioned systems still around (e.g. SunOS4) don't have strerror()
in their libraries, but can provide the same facility by this simple
alternative function. */

char *
strerror(int n)
{
if (n < 0 || n >= sys_nerr) return "unknown error number";
return sys_errlist[n];
}
#endif /* STRERROR_FROM_ERRLIST */



#ifndef OS_STRSIGNAL
/*************************************************
*      Provide strsignal() for systems without   *
*************************************************/

/* Some systems have strsignal() to turn signal numbers into names; others
may have other means of doing this. This function is used for those systems
that have nothing. It provides a basic translation for the common standard
signal numbers. I've been extra cautious with the ifdef's here. Probably more
than is necessary... */

const char *
os_strsignal(const int n)
{
switch (n)
  {
  #ifdef SIGHUP
  case SIGHUP:  return "hangup";
  #endif

  #ifdef SIGINT
  case SIGINT:  return "interrupt";
  #endif

  #ifdef SIGQUIT
  case SIGQUIT: return "quit";
  #endif

  #ifdef SIGILL
  case SIGILL:  return "illegal instruction";
  #endif

  #ifdef SIGTRAP
  case SIGTRAP: return "trace trap";
  #endif

  #ifdef SIGABRT
  case SIGABRT: return "abort";
  #endif

  #ifdef SIGEMT
  case SIGEMT:  return "EMT instruction";
  #endif

  #ifdef SIGFPE
  case SIGFPE:  return "arithmetic exception";
  #endif

  #ifdef SIGKILL
  case SIGKILL: return "killed";
  #endif

  #ifdef SIGBUS
  case SIGBUS:  return "bus error";
  #endif

  #ifdef SIGSEGV
  case SIGSEGV: return "segmentation fault";
  #endif

  #ifdef SIGSYS
  case SIGSYS:  return "bad system call";
  #endif

  #ifdef SIGPIPE
  case SIGPIPE: return "broken pipe";
  #endif

  #ifdef SIGALRM
  case SIGALRM: return "alarm";
  #endif

  #ifdef SIGTERM
  case SIGTERM: return "terminated";
  #endif

  #ifdef SIGUSR1
  case SIGUSR1: return "user signal 1";
  #endif

  #ifdef SIGUSR2
  case SIGUSR2: return "user signal 2";
  #endif

  #ifdef SIGCHLD
  case SIGCHLD: return "child stop or exit";
  #endif

  #ifdef SIGPWR
  case SIGPWR:  return "power fail/restart";
  #endif

  #ifdef SIGURG
  case SIGURG:  return "urgent condition on I/O channel";
  #endif

  #ifdef SIGSTOP
  case SIGSTOP: return "stop";
  #endif

  #ifdef SIGTSTP
  case SIGTSTP: return "stop from tty";
  #endif

  #ifdef SIGXCPU
  case SIGXCPU: return "exceeded CPU limit";
  #endif

  #ifdef SIGXFSZ
  case SIGXFSZ: return "exceeded file size limit";
  #endif

  default:      return "unrecognized signal number";
  }
}
#endif /* OS_STRSIGNAL */



#ifndef OS_STREXIT
/*************************************************
*      Provide strexit() for systems without     *
*************************************************/

/* Actually, I don't know of any system that has a strexit() function to turn
exit codes into text, but this function is implemented this way so that if any
OS does have such a thing, it could be used instead of this build-in one. */

const char *
os_strexit(const int n)
{
switch (n)
  {
  /* On systems without sysexits.h we can assume only those exit codes
  that are given a default value in exim.h. */

  #ifndef NO_SYSEXITS
  case EX_USAGE:       return "(could mean usage or syntax error)";
  case EX_DATAERR:     return "(could mean error in input data)";
  case EX_NOINPUT:     return "(could mean input data missing)";
  case EX_NOUSER:      return "(could mean user nonexistent)";
  case EX_NOHOST:      return "(could mean host nonexistent)";
  case EX_SOFTWARE:    return "(could mean internal software error)";
  case EX_OSERR:       return "(could mean internal operating system error)";
  case EX_OSFILE:      return "(could mean system file missing)";
  case EX_IOERR:       return "(could mean input/output error)";
  case EX_PROTOCOL:    return "(could mean protocol error)";
  case EX_NOPERM:      return "(could mean permission denied)";
  #endif

  case EX_EXECFAILED:  return "(could mean unable to exec or command does not exist)";
  case EX_UNAVAILABLE: return "(could mean service or program unavailable)";
  case EX_CANTCREAT:   return "(could mean can't create output file)";
  case EX_TEMPFAIL:    return "(could mean temporary error)";
  case EX_CONFIG:      return "(could mean configuration error)";
  default:             return "";
  }
}
#endif /* OS_STREXIT */




/***********************************************************
*                   Load average function                  *
***********************************************************/

/* Although every Unix seems to have a different way of getting the load
average, a number of them have things in common. Some common variants are
provided below, but if an OS has unique requirements it can be handled in
a specific os.c file. What is required is a function called os_getloadavg
which takes no arguments and passes back the load average * 1000 as an int,
or -1 if no data is available. */


/* ----------------------------------------------------------------------- */
/* If the OS has got a BSD getloadavg() function, life is very easy. */

#if !defined(OS_LOAD_AVERAGE) && defined(HAVE_BSD_GETLOADAVG)
#define OS_LOAD_AVERAGE

int
os_getloadavg(void)
{
double avg;
int loads = getloadavg (&avg, 1);
if (loads != 1) return -1;
return (int)(avg * 1000.0);
}
#endif
/* ----------------------------------------------------------------------- */



/* ----------------------------------------------------------------------- */
/* Only SunOS5 has the kstat functions as far as I know, but put the code
here as there is the -hal variant, and other systems might follow this road one
day. */

#if !defined(OS_LOAD_AVERAGE) && defined(HAVE_KSTAT)
#define OS_LOAD_AVERAGE

#include <kstat.h>

int
os_getloadavg(void)
{
int avg;
kstat_ctl_t *kc;
kstat_t *ksp;
kstat_named_t *kn;

if ((kc = kstat_open()) == NULL ||
    (ksp = kstat_lookup(kc, LOAD_AVG_KSTAT_MODULE, 0, LOAD_AVG_KSTAT))
        == NULL ||
     kstat_read(kc, ksp, NULL) < 0 ||
    (kn = kstat_data_lookup(ksp, LOAD_AVG_SYMBOL)) == NULL)
  return -1;

avg = (int)(((double)(kn->LOAD_AVG_FIELD)/FSCALE) * 1000.0);

kstat_close(kc);
return avg;
}

#endif
/* ----------------------------------------------------------------------- */



/* ----------------------------------------------------------------------- */
/* Handle OS where a kernel symbol has to be read from /dev/kmem */

#if !defined(OS_LOAD_AVERAGE) && defined(HAVE_DEV_KMEM)
#define OS_LOAD_AVERAGE

#include <nlist.h>

static int  avg_kd = -1;
static long avg_offset;

int
os_getloadavg(void)
{
LOAD_AVG_TYPE avg;

if (avg_kd < 0)
  {
  struct nlist nl[2];
  nl[0].n_name = LOAD_AVG_SYMBOL;
  nl[1].n_name = "";
  nlist (KERNEL_PATH, nl);
  avg_offset = (long)nl[0].n_value;
  avg_kd = open ("/dev/kmem", 0);
  if (avg_kd < 0) return -1;
  (void) fcntl(avg_kd, F_SETFD, FD_CLOEXEC);
  }

if (lseek (avg_kd, avg_offset, 0) == -1L
    || read (avg_kd, CS (&avg), sizeof (avg)) != sizeof(avg))
  return -1;

return (int)(((double)avg/FSCALE)*1000.0);
}

#endif
/* ----------------------------------------------------------------------- */



/* ----------------------------------------------------------------------- */
/* If nothing is known about this OS, then the load average facility is
not available. */

#ifndef OS_LOAD_AVERAGE

int
os_getloadavg(void)
{
return -1;
}

#endif

/* ----------------------------------------------------------------------- */



#if !defined FIND_RUNNING_INTERFACES
/*************************************************
*     Find all the running network interfaces    *
*************************************************/

/* Finding all the running interfaces is something that has os-dependent
tweaks, even in the IPv4 case, and it gets worse for IPv6, which is why this
code is now in the os-dependent source file. There is a common function which
works on most OS (except IRIX) for IPv4 interfaces, and, with some variations
controlled by macros, on at least one OS for IPv6 and IPv4 interfaces. On Linux
with IPv6, the common function is used for the IPv4 interfaces and additional
code used for IPv6. Consequently, the real function is called
os_common_find_running_interfaces() so that it can be called from the Linux
function. On non-Linux systems, the macro for os_find_running_interfaces just
calls the common function; on Linux it calls the Linux function.

This function finds the addresses of all the running interfaces on the machine.
A chain of blocks containing the textual form of the addresses is returned.

getifaddrs() provides a sane consistent way to query this on modern OSs,
otherwise fall back to a maze of twisty ioctl() calls

Arguments:    none
Returns:      a chain of ip_address_items, each pointing to a textual
              version of an IP address, with the port field set to zero
*/


#ifndef NO_FIND_INTERFACES

#ifdef HAVE_GETIFADDRS

#include <ifaddrs.h>

ip_address_item *
os_common_find_running_interfaces(void)
{
struct ifaddrs *ifalist = NULL;
ip_address_item *yield = NULL;
ip_address_item *last = NULL;
ip_address_item  *next;

if (getifaddrs(&ifalist) != 0)
  log_write(0, LOG_PANIC_DIE, "Unable to call getifaddrs: %d %s",
    errno, strerror(errno));

struct ifaddrs *ifa;
for (ifa = ifalist; ifa != NULL; ifa = ifa->ifa_next)
  {
  if (ifa->ifa_addr->sa_family != AF_INET
#if HAVE_IPV6
    && ifa->ifa_addr->sa_family != AF_INET6
#endif /* HAVE_IPV6 */
    )
    continue;

  if ( !(ifa->ifa_flags & IFF_UP) ) /* Only want 'UP' interfaces */
    continue;

  /* Create a data block for the address, fill in the data, and put it on the
  chain. */

  next = store_get(sizeof(ip_address_item));
  next->next = NULL;
  next->port = 0;
  (void)host_ntoa(-1, ifa->ifa_addr, next->address, NULL);

  if (yield == NULL)
    yield = last = next;
  else
    {
    last->next = next;
    last = next;
    }

  DEBUG(D_interface) debug_printf("Actual local interface address is %s (%s)\n",
    last->address, ifa->ifa_name);
  }

/* free the list of addresses, and return the chain of data blocks. */

freeifaddrs (ifalist);
return yield;
}

#else /* HAVE_GETIFADDRS */

/*
Problems:

  (1) Solaris 2 has the SIOGIFNUM call to get the number of interfaces, but
  other OS (including Solaris 1) appear not to. So just screw in a largeish
  fixed number, defined by MAX_INTERFACES. This is in the config.h file and
  can be changed in Local/Makefile. Unfortunately, the www addressing scheme
  means that some hosts have a very large number of virtual interfaces. Such
  hosts are recommended to set local_interfaces to avoid problems with this.

  (2) If the standard code is run on IRIX, it does not return any alias
  interfaces. There is special purpose code for that operating system, which
  uses the sysctl() function. The code is in OS/os.c-IRIX, and this code isn't
  used on that OS.

  (3) Some experimental/developing OS (e.g. GNU/Hurd) do not have any means
  of finding the interfaces. If NO_FIND_INTERFACES is set, a fudge-up is used
  instead.

  (4) Some operating systems set the IP address in what SIOCGIFCONF returns;
  others do not, and require SIOCGIFADDR to be called to get it. For most of
  the former, calling the latter does no harm, but it causes grief on Linux and
  BSD systems in the case of IP aliasing, so a means of cutting it out is
  provided.
*/

/* If there is IPv6 support, and SIOCGLIFCONF is defined, define macros to
use these new, longer versions of the old IPv4 interfaces. Otherwise, define
the macros to use the historical versions. */

#if HAVE_IPV6 && defined SIOCGLIFCONF
#define V_ifconf        lifconf
#define V_ifreq         lifreq
#define V_GIFADDR       SIOCGLIFADDR
#define V_GIFCONF       SIOCGLIFCONF
#define V_GIFFLAGS      SIOCGLIFFLAGS
#define V_ifc_buf       lifc_buf
#define V_ifc_family    lifc_family
#define V_ifc_flags     lifc_flags
#define V_ifc_len       lifc_len
#define V_ifr_addr      lifr_addr
#define V_ifr_flags     lifr_flags
#define V_ifr_name      lifr_name
#define V_FAMILY_QUERY  AF_UNSPEC
#define V_family        ss_family
#else
#define V_ifconf        ifconf
#define V_ifreq         ifreq
#define V_GIFADDR       SIOCGIFADDR
#define V_GIFCONF       SIOCGIFCONF
#define V_GIFFLAGS      SIOCGIFFLAGS
#define V_ifc_buf       ifc_buf
#define V_ifc_family    ifc_family
#define V_ifc_flags     ifc_flags
#define V_ifc_len       ifc_len
#define V_ifr_addr      ifr_addr
#define V_ifr_flags     ifr_flags
#define V_ifr_name      ifr_name
#define V_family        sa_family
#endif

/* In all cases of IPv6 support, use an IPv6 socket. Otherwise (at least on
Solaris 8) the call to read the flags doesn't work for IPv6 interfaces. If
we find we can't actually make an IPv6 socket, the code will revert to trying
an IPv4 socket. */

#if HAVE_IPV6
#define FAMILY          AF_INET6
#else
#define FAMILY          AF_INET
#endif

/* OK, after all that preliminary stuff, here's the code. */

ip_address_item *
os_common_find_running_interfaces(void)
{
struct V_ifconf ifc;
struct V_ifreq ifreq;
int vs;
ip_address_item *yield = NULL;
ip_address_item *last = NULL;
ip_address_item  *next;
char *cp;
char buf[MAX_INTERFACES*sizeof(struct V_ifreq)];
struct sockaddr *addrp;
size_t len = 0;
char addrbuf[512];

/* We have to create a socket in order to do ioctls on it to find out
what we want to know. */

if ((vs = socket(FAMILY, SOCK_DGRAM, 0)) < 0)
  {
  #if HAVE_IPV6
  DEBUG(D_interface)
    debug_printf("Unable to create IPv6 socket to find interface addresses:\n  "
      "error %d %s\nTrying for an IPv4 socket\n", errno, strerror(errno));
  vs = socket(AF_INET, SOCK_DGRAM, 0);
  if (vs < 0)
  #endif
  log_write(0, LOG_PANIC_DIE, "Unable to create IPv4 socket to find interface "
    "addresses: %d %s", errno, strerror(errno));
  }

/* Get the interface configuration. Some additional data is required when the
new structures are in use. */

ifc.V_ifc_len = sizeof(buf);
ifc.V_ifc_buf = buf;

#ifdef V_FAMILY_QUERY
ifc.V_ifc_family = V_FAMILY_QUERY;
ifc.V_ifc_flags = 0;
#endif

if (ioctl(vs, V_GIFCONF, CS &ifc) < 0)
  log_write(0, LOG_PANIC_DIE, "Unable to get interface configuration: %d %s",
    errno, strerror(errno));

/* If the buffer is big enough, the ioctl sets the value of ifc.V_ifc_len to
the amount actually used. If the buffer isn't big enough, at least on some
operating systems, ifc.V_ifc_len still gets set to correspond to the total
number of interfaces, even though they don't all fit in the buffer. */

if (ifc.V_ifc_len > sizeof(buf))
  {
  ifc.V_ifc_len = sizeof(buf);
  DEBUG(D_interface)
    debug_printf("more than %d interfaces found: remainder not used\n"
      "(set MAX_INTERFACES in Local/Makefile and rebuild if you want more)\n",
      MAX_INTERFACES);
  }

/* For each interface, check it is an IP interface, get its flags, and see if
it is up; if not, skip.

BSD systems differ from others in what SIOCGIFCONF returns. Other systems
return a vector of ifreq structures whose size is as defined by the structure.
BSD systems allow sockaddrs to be longer than their sizeof, which in turn makes
the ifreq structures longer than their sizeof. The code below has its origins
in amd and ifconfig; it uses the sa_len field of each sockaddr to determine
each item's length.

This is complicated by the fact that, at least on BSD systems, the data in the
buffer is not guaranteed to be aligned. Thus, we must first copy the basic
struct to some aligned memory before looking at the field in the fixed part to
find its length, and then recopy the correct length. */

for (cp = buf; cp < buf + ifc.V_ifc_len; cp += len)
  {
  memcpy(CS &ifreq, cp, sizeof(ifreq));

  #ifndef HAVE_SA_LEN
  len = sizeof(struct V_ifreq);

  #else
  len = ((ifreq.ifr_addr.sa_len > sizeof(ifreq.ifr_addr))?
          ifreq.ifr_addr.sa_len : sizeof(ifreq.ifr_addr)) +
         sizeof(ifreq.V_ifr_name);
  if (len > sizeof(addrbuf))
    log_write(0, LOG_PANIC_DIE, "Address for %s interface is absurdly long",
        ifreq.V_ifr_name);

  #endif

  /* If not an IP interface, skip */

  if (ifreq.V_ifr_addr.V_family != AF_INET
  #if HAVE_IPV6
    && ifreq.V_ifr_addr.V_family != AF_INET6
  #endif
    ) continue;

  /* Get the interface flags, and if the interface is down, continue. Formerly,
  we treated the inability to get the flags as a panic-die error. However, it
  seems that on some OS (Solaris 9 being the case noted), it is possible to
  have an interface in this list for which this call fails because the
  interface hasn't been "plumbed" to any protocol (IPv4 or IPv6). Therefore,
  we now just treat this case as "down" as well. */

  if (ioctl(vs, V_GIFFLAGS, CS &ifreq) < 0)
    {
    continue;
    /*************
    log_write(0, LOG_PANIC_DIE, "Unable to get flags for %s interface: %d %s",
      ifreq.V_ifr_name, errno, strerror(errno));
    *************/
    }
  if ((ifreq.V_ifr_flags & IFF_UP) == 0) continue;

  /* On some operating systems we have to get the IP address of the interface
  by another call. On others, it's already there, but we must copy the full
  length because we only copied the basic length above, and anyway,
  GIFFLAGS may have wrecked the data. */

  #ifndef SIOCGIFCONF_GIVES_ADDR
  if (ioctl(vs, V_GIFADDR, CS &ifreq) < 0)
    log_write(0, LOG_PANIC_DIE, "Unable to get IP address for %s interface: "
      "%d %s", ifreq.V_ifr_name, errno, strerror(errno));
  addrp = &ifreq.V_ifr_addr;

  #else
  memcpy(addrbuf, cp + offsetof(struct V_ifreq, V_ifr_addr),
    len - sizeof(ifreq.V_ifr_name));
  addrp = (struct sockaddr *)addrbuf;
  #endif

  /* Create a data block for the address, fill in the data, and put it on the
  chain. */

  next = store_get(sizeof(ip_address_item));
  next->next = NULL;
  next->port = 0;
  (void)host_ntoa(-1, addrp, next->address, NULL);

  if (yield == NULL) yield = last = next; else
    {
    last->next = next;
    last = next;
    }

  DEBUG(D_interface) debug_printf("Actual local interface address is %s (%s)\n",
    last->address, ifreq.V_ifr_name);
  }

/* Close the socket, and return the chain of data blocks. */

(void)close(vs);
return yield;
}

#endif /* HAVE_GETIFADDRS */

#else  /* NO_FIND_INTERFACES */

/* Some experimental or developing OS (e.g. GNU/Hurd) do not have the ioctls,
and there is no other way to get a list of the (IP addresses of) local
interfaces. We just return the loopback address(es). */

ip_address_item *
os_common_find_running_interfaces(void)
{
ip_address_item *yield = store_get(sizeof(address_item));
yield->address = US"127.0.0.1";
yield->port = 0;
yield->next = NULL;

#if HAVE_IPV6
yield->next = store_get(sizeof(address_item));
yield->next->address = US"::1";
yield->next->port = 0;
yield->next->next = NULL;
#endif

DEBUG(D_interface) debug_printf("Unable to find local interface addresses "
  "on this OS: returning loopback address(es)\n");
return yield;
}

#endif /* NO_FIND_INTERFACES */
#endif /* FIND_RUNNING_INTERFACES */




/* ----------------------------------------------------------------------- */

/***********************************************************
*                 DNS Resolver Base Finder                 *
***********************************************************/

/* We need to be able to set options for the system resolver(5), historically
made available as _res.  At least one OS (NetBSD) now no longer provides this
directly, instead making you call a function per thread to get a handle.
Other OSs handle thread-safe resolver differently, in ways which fail if the
programmer creates their own structs. */

#if !defined(OS_GET_DNS_RESOLVER_RES) && !defined(COMPILE_UTILITY)

#include <resolv.h>

/* confirmed that res_state is typedef'd as a struct* on BSD and Linux, will
find out how unportable it is on other OSes, but most resolver implementations
should be descended from ISC's bind.

Linux and BSD do:
  define _res (*__res_state())
identically.  We just can't rely on __foo functions.  It's surprising that use
of _res has been as portable as it has, for so long.

So, since _res works everywhere, and everything can decode the struct, I'm
going to gamble that res_state is a typedef everywhere and use that as the
return type.
*/

res_state
os_get_dns_resolver_res(void)
{
  return &_res;
}

#endif /* OS_GET_DNS_RESOLVER_RES */

/* ----------------------------------------------------------------------- */

/***********************************************************
*                 unsetenv()                               *
***********************************************************/

/* Most modern systems define int unsetenv(const char*),
* some don't. */

#if !defined(OS_UNSETENV)
int
os_unsetenv(const unsigned char * name)
{
return unsetenv(CS name);
}
#endif

/* ----------------------------------------------------------------------- */

/***********************************************************
*               getcwd()                                   *
***********************************************************/

/* Glibc allows getcwd(NULL, 0) to do auto-allocation. Some systems
do auto-allocation, but need the size of the buffer, and others
may not even do this. If the OS supports getcwd(NULL, 0) we'll use
this, for all other systems we provide our own getcwd() */

#if !defined(OS_GETCWD)
unsigned char *
os_getcwd(unsigned char * buffer, size_t size)
{
return US  getcwd(CS buffer, size);
}
#else
#ifndef PATH_MAX
# define PATH_MAX 4096
#endif
unsigned char *
os_getcwd(unsigned char * buffer, size_t size)
{
char * b = CS buffer;

if (!size) size = PATH_MAX;
if (!b && !(b = malloc(size))) return NULL;
if (!(b = getcwd(b, size))) return NULL;
return buffer ? buffer : realloc(b, strlen(b) + 1);
}
#endif

/* ----------------------------------------------------------------------- */




/*************************************************
**************************************************
*             Stand-alone test program           *
**************************************************
*************************************************/


#ifdef STAND_ALONE

#ifdef CLOCKS_PER_SEC
#define REAL_CLOCK_TICK CLOCKS_PER_SEC
#else
  #ifdef CLK_TCK
  #define REAL_CLOCK_TICK CLK_TCK
  #else
  #define REAL_CLOCK_TICK 1000000   /* SunOS4 */
  #endif
#endif


int main(int argc, char **argv)
{
char buffer[128];
int fd = fileno(stdin);
int rc;

printf("Testing restarting signal; wait for handler message, then type a line\n");
strcpy(buffer, "*** default ***\n");
os_restarting_signal(SIGALRM, sigalrm_handler);
ALARM(2);
if ((rc = read(fd, buffer, sizeof(buffer))) < 0)
  printf("No data read\n");
else
  {
  buffer[rc] = 0;
  printf("Read: %s", buffer);
  }
ALARM_CLR(0);

printf("Testing non-restarting signal; should read no data after handler message\n");
strcpy(buffer, "*** default ***\n");
os_non_restarting_signal(SIGALRM, sigalrm_handler);
ALARM(2);
if ((rc = read(fd, buffer, sizeof(buffer))) < 0)
  printf("No data read\n");
else
  {
  buffer[rc] = 0;
  printf("Read: %s", buffer);
  }
ALARM_CLR(0);

printf("Testing load averages (last test - ^C to kill)\n");
for (;;)
  {
  int avg;
  clock_t used;
  clock_t before = clock();
  avg = os_getloadavg();
  used = clock() - before;
  printf("cpu time = %.2f ", (double)used/REAL_CLOCK_TICK);
  if (avg < 0)
    {
    printf("load average not available\n");
    break;
    }
  printf("load average = %.2f\n", (double)avg/1000.0);
  sleep(2);
  }
return 0;
}

#endif

/* End of os.c */
