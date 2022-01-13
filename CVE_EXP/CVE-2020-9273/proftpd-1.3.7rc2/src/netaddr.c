/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003-2017 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Network address routines */

#include "conf.h"

#if HAVE_NET_IF_H
# include <net/if.h>
#endif
#if HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif

/* Define an IPv4 equivalent of the IN6_IS_ADDR_LOOPBACK macro. */
#undef IN_IS_ADDR_LOOPBACK
#define IN_IS_ADDR_LOOPBACK(a) \
  ((((unsigned long int) ntohl((a)->s_addr)) & 0xff000000) == 0x7f000000)

static pr_netaddr_t sess_local_addr;
static int have_sess_local_addr = FALSE;

static pr_netaddr_t sess_remote_addr;
static char sess_remote_name[PR_TUNABLE_BUFFER_SIZE];
static int have_sess_remote_addr = FALSE;

/* Do reverse DNS lookups? */
static int reverse_dns = 1;

/* Use IPv6? */
#ifdef PR_USE_IPV6
static int use_ipv6 = TRUE;
#else
static int use_ipv6 = FALSE;
#endif /* PR_USE_IPV6 */

static char localaddr_str[PR_TUNABLE_BUFFER_SIZE];
static int have_localaddr_str = FALSE;

static pool *netaddr_pool = NULL;
static pr_table_t *netaddr_iptab = NULL;
static pr_table_t *netaddr_dnstab = NULL;

static const char *trace_channel = "dns";

/* Netaddr cache management */
static array_header *netaddr_dnscache_get(pool *p, const char *ip_str) {
  array_header *res = NULL;

  if (netaddr_dnstab != NULL) {
    const void *v;

    v = pr_table_get(netaddr_dnstab, ip_str, NULL);
    if (v != NULL) {
      res = (array_header *) v;

      pr_trace_msg(trace_channel, 4,
        "using %d DNS %s from netaddr DNS cache for IP address '%s'",
        res->nelts, res->nelts != 1 ? "names" : "name", ip_str);

      if (p) {
        /* If the caller provided a pool, return a copy of the array. */
        return copy_array_str(p, res);
      }

      return res;
    }
  }

  pr_trace_msg(trace_channel, 12,
    "no DNS names found in netaddr DNS cache for IP address '%s'", ip_str);
  errno = ENOENT;
  return NULL;
}

static void netaddr_dnscache_set(const char *ip_str, const char *dns_name) {
  if (netaddr_dnstab) {
    void *v = NULL;
    array_header *res = NULL;
    int add_list = FALSE;

    res = netaddr_dnscache_get(NULL, ip_str);
    if (res == NULL) {
      /* No existing entries for this IP address yet. */
      res = make_array(netaddr_pool, 1, sizeof(char *));
      add_list = TRUE;

    } else {
      register unsigned int i;
      char **names;

      /* Check for duplicates. */
      names = res->elts;
      for (i = 0; i < res->nelts; i++) {
        if (names[i] != NULL) {
          if (strcmp(names[i], dns_name) == 0) {
            pr_trace_msg(trace_channel, 5,
              "DNS name '%s' for IP address '%s' already stashed in the "
              "netaddr DNS cache", dns_name, ip_str);
            return;
          }
        }
      }
    }

    *((char **) push_array(res)) = pstrdup(netaddr_pool, dns_name);
    v = res;

    if (add_list) { 
      if (pr_table_add(netaddr_dnstab, pstrdup(netaddr_pool, ip_str), v,
          sizeof(array_header *)) < 0) {
        pr_trace_msg(trace_channel, 3,
          "error adding DNS name '%s' for IP address '%s' to the netaddr "
          "DNS cache: %s", dns_name, ip_str, strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 5,
          "stashed DNS name '%s' for IP address '%s' in the netaddr DNS cache",
          dns_name, ip_str);
      }

    } else {
      pr_trace_msg(trace_channel, 5,
        "stashed DNS name '%s' for IP address '%s' in the netaddr DNS cache",
        dns_name, ip_str);
    }
  }

  return;
}

static pr_netaddr_t *netaddr_ipcache_get(pool *p, const char *name) {
  pr_netaddr_t *res = NULL;

  if (netaddr_iptab != NULL) {
    const void *v;

    v = pr_table_get(netaddr_iptab, name, NULL);
    if (v != NULL) {
      res = (pr_netaddr_t *) v;
      pr_trace_msg(trace_channel, 4,
        "using IP address '%s' from netaddr IP cache for name '%s'",
        pr_netaddr_get_ipstr(res), name);

      /* We return a copy of the cache's netaddr_t, if the caller provided
       * a pool for duplication.
       */
      if (p != NULL) {
        pr_netaddr_t *dup_res = NULL;

        dup_res = pr_netaddr_dup(p, res);
        if (dup_res == NULL) {
          pr_log_debug(DEBUG0, "error duplicating address for name '%s' "
            "from cache: %s", name, strerror(errno));
        }

        return dup_res;
      }

      return res;
    }
  }

  pr_trace_msg(trace_channel, 2,
    "no IP address found in netaddr IP cache for name '%s'", name);
  errno = ENOENT;
  return NULL;
}

static int netaddr_ipcache_set(const char *name, const pr_netaddr_t *na) {
  if (netaddr_iptab != NULL) {
    int count = 0;
    void *v = NULL;

    /* We store an internal copy of the netaddr_t in the cache. */
    v = pr_netaddr_dup(netaddr_pool, na);
    if (v == NULL) {
      return -1;
    }

    count = pr_table_exists(netaddr_iptab, name);
    if (count <= 0) {
      if (pr_table_add(netaddr_iptab, pstrdup(netaddr_pool, name), v,
          sizeof(pr_netaddr_t *)) < 0) {
        pr_trace_msg(trace_channel, 3,
          "error adding IP address '%s' for name '%s' to the netaddr "
          "IP cache: %s", pr_netaddr_get_ipstr(na), name,
          strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 5,
          "stashed IP address '%s' for name '%s' in the netaddr IP cache",
          pr_netaddr_get_ipstr(v), name);
      }

    } else {
      if (pr_table_set(netaddr_iptab, pstrdup(netaddr_pool, name), v,
          sizeof(pr_netaddr_t *)) < 0) {
        pr_trace_msg(trace_channel, 3,
          "error setting IP address '%s' for name '%s' in the netaddr "
          "IP cache: %s", pr_netaddr_get_ipstr(na), name, strerror(errno));
      }
    }
  }

  return 0;
}

/* Provide replacements for needed functions. */

#if !defined(HAVE_GETNAMEINFO) || defined(PR_USE_GETNAMEINFO)
int pr_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
    size_t hostlen, char *serv, size_t servlen, int flags) {

  struct sockaddr_in *sai = (struct sockaddr_in *) sa;

  if (!sai || sai->sin_family != AF_INET)
    return EAI_FAMILY;

  if (serv != NULL && servlen > (size_t) 1)
    pr_snprintf(serv, servlen, "%lu", (unsigned long) ntohs(sai->sin_port));

  if (host != NULL && hostlen > (size_t) 1) {
    struct hostent *he = NULL;

    if ((flags & NI_NUMERICHOST) == 0 &&
        (he = gethostbyaddr((const char *) &(sai->sin_addr),
          sizeof(sai->sin_addr), AF_INET)) != NULL &&
        he->h_name != NULL &&
        *he->h_name != 0) {

      if (strlen(he->h_name) >= hostlen)
          goto handle_numeric_ip;
      sstrncpy(host, he->h_name, hostlen);

    } else {
      char *ipstr = NULL;

      handle_numeric_ip:
      ipstr = inet_ntoa(sai->sin_addr);
      if (ipstr == NULL)
        return EAI_SYSTEM;

      if (strlen(ipstr) >= hostlen)
        return EAI_FAIL;

      sstrncpy(host, ipstr, hostlen);
    }
  }

  return 0;
}
#endif /* HAVE_GETNAMEINFO or PR_USE_GETNAMEINFO */

#if !defined(HAVE_GETADDRINFO) || defined(PR_USE_GETADDRINFO)
int pr_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res) {

  struct addrinfo *ans = NULL;
  struct sockaddr_in *saddr = NULL;
  const char *proto_name = "tcp";
  int socktype = SOCK_STREAM;
  unsigned short port = 0;

  if (!res)
    return EAI_FAIL;
  *res = NULL;

  ans = malloc(sizeof(struct addrinfo));
  if (ans == NULL)
    return EAI_MEMORY;

  saddr = malloc(sizeof(struct sockaddr_in));
  if (saddr == NULL) {
    free(ans);
    return EAI_MEMORY;
  }

  ans->ai_family = AF_INET;
  ans->ai_addrlen = sizeof *saddr;
  ans->ai_addr = (struct sockaddr *) saddr;
  ans->ai_next = NULL;
  memset(saddr, 0, sizeof(*saddr));
  saddr->sin_family = AF_INET;

  if (hints != NULL) {
    struct protoent *pe = NULL;

    if ((pe = getprotobynumber(hints->ai_protocol)) != NULL &&
         pe->p_name != NULL &&
         *pe->p_name != 0)
      proto_name = pe->p_name;

    if (hints->ai_socktype != 0) {
      socktype = hints->ai_socktype;

    } else if (strncasecmp(proto_name, "udp", 4) == 0) {
      socktype = SOCK_DGRAM;
    }
  }

  if (service != NULL) {
    struct servent *se = NULL;

    if ((se = getservbyname(service, proto_name)) != NULL &&
        se->s_port > 0)
      port = se->s_port;

    else if ((port = (unsigned short) strtoul(service, NULL, 0)) <= 0 ||
        port > 65535)
      port = 0;
  }

  if (hints != NULL &&
      (hints->ai_flags & AI_PASSIVE) != 0)
    saddr->sin_addr.s_addr = htonl(INADDR_ANY);

  if (node != NULL) {
    struct hostent *he = NULL;

    if ((he = gethostbyname(node)) != NULL &&
         he->h_addr_list != NULL &&
         he->h_addr_list[0] != NULL &&
         he->h_length > 0 &&
         he->h_length <= (int) sizeof(saddr->sin_addr))
      memcpy(&saddr->sin_addr, he->h_addr_list[0], he->h_length);
  }

  ans->ai_socktype = socktype;
  saddr->sin_port = htons(port);
  *res = ans;

  return 0;
}

void pr_freeaddrinfo(struct addrinfo *ai) {
  if (!ai)
    return;

  if (ai->ai_addr != NULL) {
    free(ai->ai_addr);
    ai->ai_addr = NULL;
  }
  free(ai);
}
#endif /* HAVE_GETADDRINFO or PR_USE_GETADDRINFO */

#if !defined(HAVE_INET_NTOP)
const char *pr_inet_ntop(int af, const void *src, char *dst, size_t len) {
  char *res;

  if (af != AF_INET) {
    errno = EAFNOSUPPORT;
    return NULL;
  }

  res = inet_ntoa(*((struct in_addr *) src));
  if (res == NULL)
    return NULL;

  memcpy(dst, res, len);
  return dst;
}
#endif /* !HAVE_INET_NTOP */

#if !defined(HAVE_INET_PTON)
int pr_inet_pton(int af, const char *src, void *dst) {
  unsigned long res;

  if (af != AF_INET) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  /* inet_aton(3) would be better. However, it is not ubiquitous.  */
  res = inet_addr(src);
  if (res == INADDR_NONE ||
      res == 0)
    return 0;

  memcpy(dst, &res, sizeof(res));
  return 1;
}
#endif /* !HAVE_INET_PTON */

static void *get_v4inaddr(const pr_netaddr_t *na) {

  /* This function is specifically for IPv4 clients (when gethostbyname2(2) is
   * present) that have an IPv4-mapped IPv6 address, when performing reverse
   * DNS checks.  This function is called iff the given netaddr object is
   * indeed an IPv4-mapped IPv6 address.  IPv6 address have 128 bits in their
   * sin6_addr field.  For IPv4-mapped IPv6 addresses, the relevant 32 bits
   * are the last of those 128 bits (or, alternatively, the last 4 bytes of
   * those 16 bytes); hence the read of 12 bytes after the start of the
   * sin6_addr pointer.
   */

  return (((char *) pr_netaddr_get_inaddr(na)) + 12);
}

/* Validate anything returned from the 'outside', since it's untrusted
 * information.
 */
char *pr_netaddr_validate_dns_str(char *buf) {
  char *p;

  if (buf == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Validate anything returned from a DNS. */
  for (p = buf; p && *p; p++) {

    /* Per RFC requirements, these are all that are valid from a DNS. */
    if (!PR_ISALNUM(*p) &&
        *p != '.' &&
        *p != '-'
#ifdef PR_USE_IPV6
        && *p != ':'
#endif /* PR_USE_IPV6 */
        ) {

      /* We set it to _ because we know that's an invalid, yet safe, option
       * for a DNS entry.
       */
      *p = '_';
    }
  }

  return buf;
}

int pr_netaddr_set_reverse_dns(int enable) {
  int old_enable = reverse_dns;
  reverse_dns = enable;
  return old_enable;
}

pr_netaddr_t *pr_netaddr_alloc(pool *p) {
  if (!p) {
    errno = EINVAL;
    return NULL;
  }

  return pcalloc(p, sizeof(pr_netaddr_t));
}

void pr_netaddr_clear(pr_netaddr_t *na) {
  if (!na)
    return;

  memset(na, 0, sizeof(pr_netaddr_t));
}

pr_netaddr_t *pr_netaddr_dup(pool *p, const pr_netaddr_t *na) {
  pr_netaddr_t *dup_na;

  if (p == NULL ||
      na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  dup_na = pr_netaddr_alloc(p);

  if (pr_netaddr_set_family(dup_na, pr_netaddr_get_family(na)) < 0) {
    return NULL;
  }

  pr_netaddr_set_sockaddr(dup_na, pr_netaddr_get_sockaddr(na));  

  if (na->na_have_ipstr) {
    sstrncpy(dup_na->na_ipstr, na->na_ipstr, sizeof(dup_na->na_ipstr));
    dup_na->na_have_ipstr = 1;
  }

  if (na->na_have_dnsstr) {
    sstrncpy(dup_na->na_dnsstr, na->na_dnsstr, sizeof(dup_na->na_dnsstr));
    dup_na->na_have_dnsstr = 1;
  }

  return dup_na;
}

static pr_netaddr_t *get_addr_by_ip(pool *p, const char *name,
    array_header **addrs) {
  struct sockaddr_in v4;
  pr_netaddr_t *na = NULL;
  int res;

#ifdef PR_USE_IPV6
  if (use_ipv6) {
    struct sockaddr_in6 v6;
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;

# ifdef SIN6_LEN
    v6.sin6_len = sizeof(struct sockaddr_in6);
# endif /* SIN6_LEN */

    res = pr_inet_pton(AF_INET6, name, &v6.sin6_addr);
    if (res > 0) {
      na = (pr_netaddr_t *) pcalloc(p, sizeof(pr_netaddr_t));
      pr_netaddr_set_family(na, AF_INET6);
      pr_netaddr_set_sockaddr(na, (struct sockaddr *) &v6);
      if (addrs) {
        *addrs = NULL;
      }

      pr_trace_msg(trace_channel, 7, "'%s' resolved to IPv6 address %s", name,
        pr_netaddr_get_ipstr(na));

      if (netaddr_ipcache_set(name, na) < 0) {
        pr_trace_msg(trace_channel, 2, "error setting '%s' in cache: %s", name,
          strerror(errno));
      }

      if (netaddr_ipcache_set(pr_netaddr_get_ipstr(na), na) < 0) {
        pr_trace_msg(trace_channel, 2, "error setting '%s' in cache: %s",
          pr_netaddr_get_ipstr(na), strerror(errno));
      }

      return na;
    }
  }
#endif /* PR_USE_IPV6 */

  memset(&v4, 0, sizeof(v4));
  v4.sin_family = AF_INET;

# ifdef SIN_LEN
  v4.sin_len = sizeof(struct sockaddr_in);
# endif /* SIN_LEN */

  res = pr_inet_pton(AF_INET, name, &v4.sin_addr);
  if (res > 0) {
    na = (pr_netaddr_t *) pcalloc(p, sizeof(pr_netaddr_t));
    pr_netaddr_set_family(na, AF_INET);
    pr_netaddr_set_sockaddr(na, (struct sockaddr *) &v4);
    if (addrs) {
      *addrs = NULL;
    }

    pr_trace_msg(trace_channel, 7, "'%s' resolved to IPv4 address %s", name,
      pr_netaddr_get_ipstr(na));

    if (netaddr_ipcache_set(name, na) < 0) {
      pr_trace_msg(trace_channel, 2, "error setting '%s' in cache: %s", name,
        strerror(errno));
    }

    if (netaddr_ipcache_set(pr_netaddr_get_ipstr(na), na) < 0) {
      pr_trace_msg(trace_channel, 2, "error setting '%s' in cache: %s",
        pr_netaddr_get_ipstr(na), strerror(errno));
    }

    return na;
  }

  return NULL;
}

static pr_netaddr_t *get_addr_by_name(pool *p, const char *name,
    array_header **addrs) {
  pr_netaddr_t *na = NULL;
  int res;
  struct addrinfo hints, *info = NULL;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  pr_trace_msg(trace_channel, 7,
    "attempting to resolve '%s' to IPv4 address via DNS", name);
  res = pr_getaddrinfo(name, NULL, &hints, &info);
  if (res != 0) {
    int xerrno = errno;

    if (res != EAI_SYSTEM) {
#ifdef PR_USE_IPV6
      if (use_ipv6) {
        pr_trace_msg(trace_channel, 7,
          "unable to resolve '%s' to an IPv4 address: %s", name,
          pr_gai_strerror(res));

        info = NULL;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        pr_trace_msg(trace_channel, 7,
          "attempting to resolve '%s' to IPv6 address via DNS", name);
        res = pr_getaddrinfo(name, NULL, &hints, &info);
        if (res != 0) {
          xerrno = errno;

          if (res != EAI_SYSTEM) {
            pr_trace_msg(trace_channel, 5,
              "unable to resolve '%s' to an IPv6 address: %s", name,
              pr_gai_strerror(res));

            if (res == EAI_NONAME) {
              xerrno = ENOENT;
            }

          } else {
            pr_trace_msg(trace_channel, 1,
              "IPv6 getaddrinfo '%s' system error: [%d] %s", name,
              xerrno, strerror(xerrno));
          }
        }

      } else {
        pr_trace_msg(trace_channel, 1, "IPv4 getaddrinfo '%s' error: %s",
          name, pr_gai_strerror(res));

        if (res == EAI_NONAME) {
          xerrno = ENOENT;
        }
      }
#else
      pr_trace_msg(trace_channel, 1, "IPv4 getaddrinfo '%s' error: %s",
        name, pr_gai_strerror(res));
      if (res == EAI_NONAME) {
        xerrno = ENOENT;
      }
#endif /* PR_USE_IPV6 */

    } else {
      pr_trace_msg(trace_channel, 1,
        "IPv4 getaddrinfo '%s' system error: [%d] %s", name,
        xerrno, strerror(xerrno));
    }

    if (res != 0) {
      errno = xerrno;
      return NULL;
    }
  }

  if (info != NULL) {
    na = (pr_netaddr_t *) pcalloc(p, sizeof(pr_netaddr_t));

    /* Copy the first returned addr into na, as the return value. */
    pr_netaddr_set_family(na, info->ai_family);
    pr_netaddr_set_sockaddr(na, info->ai_addr);

    pr_trace_msg(trace_channel, 7, "resolved '%s' to %s address %s", name,
      info->ai_family == AF_INET ? "IPv4" : "IPv6",
      pr_netaddr_get_ipstr(na));

    if (netaddr_ipcache_set(name, na) < 0) {
      pr_trace_msg(trace_channel, 2, "error setting '%s' in cache: %s", name,
        strerror(errno));
    }

    if (netaddr_ipcache_set(pr_netaddr_get_ipstr(na), na) < 0) {
      pr_trace_msg(trace_channel, 2, "error setting '%s' in cache: %s",
        pr_netaddr_get_ipstr(na), strerror(errno));
    }

    if (addrs != NULL) {
      struct addrinfo *next_info = NULL;

      /* Copy any other addrs into the list. */
      if (*addrs == NULL) {
        *addrs = make_array(p, 0, sizeof(pr_netaddr_t *));
      }

      next_info = info->ai_next;
      while (next_info != NULL) {
        pr_netaddr_t **elt;

        pr_signals_handle();
        elt = push_array(*addrs);

        *elt = pcalloc(p, sizeof(pr_netaddr_t));
        pr_netaddr_set_family(*elt, next_info->ai_family);
        pr_netaddr_set_sockaddr(*elt, next_info->ai_addr);

        pr_trace_msg(trace_channel, 7, "resolved '%s' to %s address %s", name,
          next_info->ai_family == AF_INET ? "IPv4" : "IPv6",
          pr_netaddr_get_ipstr(*elt));

        next_info = next_info->ai_next;
      }
    }

    pr_freeaddrinfo(info);
  }

#ifdef PR_USE_IPV6
  if (use_ipv6 && addrs) {
    /* Do the call again, this time for IPv6 addresses.
     *
     * We make two separate getaddrinfo(3) calls, rather than one
     * with a hint of AF_UNSPEC, because of certain bugs where the use
     * of AF_UNSPEC does not function as advertised.  (I suspect this
     * bug was caused by proftpd's calling pattern, but as I could
     * not track it down, and as there are reports of AF_UNSPEC not
     * being as fast as AF_INET/AF_INET6, it just seemed easier to
     * do it this way.)
     */

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    pr_trace_msg(trace_channel, 7,
      "attempting to resolve '%s' to IPv6 address via DNS", name);
    res = pr_getaddrinfo(name, NULL, &hints, &info);
    if (res != 0) {
      int xerrno = errno;

      if (res != EAI_SYSTEM) {
        pr_trace_msg(trace_channel, 1, "IPv6 getaddrinfo '%s' error: %s",
          name, pr_gai_strerror(res));

      } else {
        pr_trace_msg(trace_channel, 1, 
          "IPv6 getaddrinfo '%s' system error: [%d] %s", name,
          xerrno, strerror(xerrno));
      }

    } else {
      /* We may have already looked up an IPv6 address as the first
       * address; we don't want to have duplicate addresses in the
       * returned list of additional addresses.
       */
      if (info != NULL) {
        struct addrinfo *next_info = NULL;

        /* Copy any other addrs into the list. */
        if (*addrs == NULL) {
          *addrs = make_array(p, 0, sizeof(pr_netaddr_t *));
        }

        next_info = info->ai_next;
        while (next_info != NULL) {
          pr_netaddr_t **elt;

          pr_signals_handle();
          elt = push_array(*addrs);

          *elt = pcalloc(p, sizeof(pr_netaddr_t));
          pr_netaddr_set_family(*elt, next_info->ai_family);
          pr_netaddr_set_sockaddr(*elt, next_info->ai_addr);

          pr_trace_msg(trace_channel, 7, "resolved '%s' to %s address %s", name,
            next_info->ai_family == AF_INET ? "IPv4" : "IPv6",
            pr_netaddr_get_ipstr(*elt));

          next_info = next_info->ai_next;
        }

        pr_freeaddrinfo(info);
      }
    }
  }
#endif /* PR_USE_IPV6 */

  return na;
}

static pr_netaddr_t *get_addr_by_device(pool *p, const char *name,
    array_header **addrs) {
#ifdef HAVE_GETIFADDRS
  struct ifaddrs *ifaddr = NULL;
  pr_netaddr_t *na = NULL;
  int res, xerrno;

  /* Try to use the given name as a device/interface name, and see if we
   * can suss out the IP address(es) to use based on that.
   */

  res = getifaddrs(&ifaddr);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error retrieving interfaces via getifaddrs(3): %s", strerror(xerrno));

  } else {
    struct ifaddrs *ifa;
    int found_device = FALSE;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      pr_signals_handle();

      /* Watch out for null ifa_addr, as when a device does not have
       * an associated address (e.g. due to not be initialized).
       */
      if (ifa->ifa_addr == NULL) {
        continue;
      }

      /* We're only looking for addresses, not stats. */
      if (ifa->ifa_addr->sa_family != AF_INET
#ifdef PR_USE_IPV6
          && ifa->ifa_addr->sa_family != AF_INET6
#endif /* PR_USE_IPV6 */
         ) {
        continue;
      }

      if (strcmp(ifa->ifa_name, name) == 0) {
        if (found_device == FALSE) {
          na = (pr_netaddr_t *) pcalloc(p, sizeof(pr_netaddr_t));

          pr_netaddr_set_family(na, ifa->ifa_addr->sa_family);
          pr_netaddr_set_sockaddr(na, ifa->ifa_addr);

          pr_trace_msg(trace_channel, 7,
            "resolved '%s' to interface with %s address %s", name,
            ifa->ifa_addr->sa_family == AF_INET ? "IPv4" : "IPv6",
            pr_netaddr_get_ipstr(na));

          found_device = TRUE;

          /* If the caller did not request additional addresses, then
           * return now.  Otherwise, we keep looking for the other
           * addresses bound to this interface.
           */
          if (addrs == NULL) {
            break;
          }

        } else {
          pr_netaddr_t **elt;

          /* We've already found the first match; this block happens
           * if the caller wants all of the addresses for this interface.
           */

          *addrs = make_array(p, 0, sizeof(pr_netaddr_t *));
          elt = push_array(*addrs);

          *elt = pcalloc(p, sizeof(pr_netaddr_t));
          pr_netaddr_set_family(*elt, ifa->ifa_addr->sa_family);
          pr_netaddr_set_sockaddr(*elt, ifa->ifa_addr);

          pr_trace_msg(trace_channel, 7,
            "resolved '%s' to interface with %s address %s", name,
            ifa->ifa_addr->sa_family == AF_INET ? "IPv4" : "IPv6",
            pr_netaddr_get_ipstr(*elt));
        }
      }
    }

    if (ifaddr != NULL) {
      freeifaddrs(ifaddr);
    }

    if (found_device) {
      return na;
    }
  }

  errno = ENOENT;
#else
  errno = ENOSYS;
#endif /* HAVE_GETIFADDRS */

  return NULL;
}

const pr_netaddr_t *pr_netaddr_get_addr2(pool *p, const char *name,
    array_header **addrs, unsigned int flags) {
  pr_netaddr_t *na = NULL;

  if (p == NULL ||
      name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 10, "resolving name '%s' to IP address",
    name);

  /* First, check our cache to see if this name has already been
   * resolved.  We only want to use the cache, though, if the caller did not
   * provide the `addrs' pointer, indicating that the caller wants to know
   * about any additional addresses for the given name.  The netaddr cache
   * is a simple cache, hidden from callers, and thus is unable to populate
   * that `addrs' pointer if the name is in the cache.
   */
  if (addrs == NULL) {
    na = netaddr_ipcache_get(p, name);
    if (na) {
      return na;
    }
  }

  /* Attempt to translate the given name into a pr_netaddr_t using
   * pr_inet_pton() first.
   *
   * First, if IPv6 support is enabled, we try to translate the name using
   * pr_inet_pton(AF_INET6) on the hopes that the given string is a valid
   * representation of an IPv6 address.  If that fails, or if IPv6 support
   * is not enabled, we try with pr_inet_pton(AF_INET).  If that fails, we
   * assume that the given name is a DNS name, and we call pr_getaddrinfo().
   */

  na = get_addr_by_ip(p, name, addrs);
  if (na != NULL) {
    return na;
  }

  /* If get_addr_by_ip() returns NULL, it means that name does not represent a
   * valid network address in the specified address family.  Usually,
   * this means that name is actually a DNS name, not an IP address
   * string.  So we treat it as a DNS name, and use getaddrinfo(3) to
   * resolve that name to its IP address(es) -- unless the EXCL_DNS flag
   * has been used, indicating that the caller does not want us resolving
   * DNS names.
   */

  if (!(flags & PR_NETADDR_GET_ADDR_FL_EXCL_DNS)) {
    na = get_addr_by_name(p, name, addrs);
    if (na != NULL) {
      return na;
    }
  }

  if (flags & PR_NETADDR_GET_ADDR_FL_INCL_DEVICE) {
    na = get_addr_by_device(p, name, addrs);
    if (na != NULL) {
      return na;
    }
  }

  pr_trace_msg(trace_channel, 8, "failed to resolve '%s' to an IP address",
    name);
  errno = ENOENT;
  return NULL;
}

const pr_netaddr_t *pr_netaddr_get_addr(pool *p, const char *name,
    array_header **addrs) {
  return pr_netaddr_get_addr2(p, name, addrs, 0);
}

int pr_netaddr_get_family(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return -1;
  }

  return na->na_family;
}

int pr_netaddr_set_family(pr_netaddr_t *na, int family) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  /* Set the family member of the appropriate sockaddr struct. */
  switch (family) {
    case AF_INET:
      na->na_addr.v4.sin_family = AF_INET;
      break;

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6) {
        na->na_addr.v6.sin6_family = AF_INET6;
        break;
      }
#endif /* PR_USE_IPV6 */

    default:
#ifdef EAFNOSUPPORT
      errno = EAFNOSUPPORT;
#else
      errno = EINVAL;
#endif
      return -1;
  }

  na->na_family = family;
  return 0;
}

size_t pr_netaddr_get_sockaddr_len(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return sizeof(struct sockaddr_in);
 
#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6)
        return sizeof(struct sockaddr_in6);
#endif /* PR_USE_IPV6 */   
  }

  errno = EPERM;
  return -1;
}

size_t pr_netaddr_get_inaddr_len(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return sizeof(struct in_addr);

#ifdef PR_USE_IPV6
    case AF_INET6:
      return sizeof(struct in6_addr);
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

struct sockaddr *pr_netaddr_get_sockaddr(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return (struct sockaddr *) &na->na_addr.v4;

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6)
        return (struct sockaddr *) &na->na_addr.v6;
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return NULL;
}

int pr_netaddr_set_sockaddr(pr_netaddr_t *na, struct sockaddr *addr) {
  if (na == NULL ||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  memset(&na->na_addr, 0, sizeof(na->na_addr));
  switch (na->na_family) {
    case AF_INET:
      memcpy(&(na->na_addr.v4), addr, sizeof(struct sockaddr_in));
      return 0;

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6) {
        memcpy(&(na->na_addr.v6), addr, sizeof(struct sockaddr_in6));
        return 0;
      }
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

int pr_netaddr_set_sockaddr_any(pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET: {
      struct in_addr in4addr_any;
      in4addr_any.s_addr = htonl(INADDR_ANY);
      na->na_addr.v4.sin_family = AF_INET;
#ifdef SIN_LEN
      na->na_addr.v4.sin_len = sizeof(struct sockaddr_in);
#endif /* SIN_LEN */
      memcpy(&na->na_addr.v4.sin_addr, &in4addr_any, sizeof(struct in_addr));
      return 0;
    }

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6) {
        na->na_addr.v6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
        na->na_addr.v6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
        memcpy(&na->na_addr.v6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
        return 0;
      }
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

void *pr_netaddr_get_inaddr(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return (void *) &na->na_addr.v4.sin_addr;

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6)
        return (void *) &na->na_addr.v6.sin6_addr;
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return NULL;
}

unsigned int pr_netaddr_get_port(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return 0;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return na->na_addr.v4.sin_port;

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6)
        return na->na_addr.v6.sin6_port;
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return 0;
}

int pr_netaddr_set_port(pr_netaddr_t *na, unsigned int port) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      na->na_addr.v4.sin_port = port;
      return 0;

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6) {
        na->na_addr.v6.sin6_port = port;
        return 0;
      }
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

int pr_netaddr_set_port2(pr_netaddr_t *na, unsigned int port) {
  return pr_netaddr_set_port(na, htons(port));
}

int pr_netaddr_cmp(const pr_netaddr_t *na1, const pr_netaddr_t *na2) {
  pool *tmp_pool = NULL;
  pr_netaddr_t *a, *b;
  int res;

  if (na1 != NULL &&
      na2 == NULL) {
    return 1;
  }

  if (na1 == NULL &&
      na2 != NULL) {
    return -1;
  }

  if (na1 == NULL &&
      na2 == NULL) {
    return 0;
  }

  if (pr_netaddr_get_family(na1) != pr_netaddr_get_family(na2)) {

    /* Cannot compare addresses from different families, unless one
     * of the netaddrs has an AF_INET family, and the other has an
     * AF_INET6 family AND is an IPv4-mapped IPv6 address.
     */

    if (pr_netaddr_is_v4mappedv6(na1) != TRUE &&
        pr_netaddr_is_v4mappedv6(na2) != TRUE) {
      errno = EINVAL;
      return -1;
    }

    if (pr_netaddr_is_v4mappedv6(na1) == TRUE) {
      tmp_pool = make_sub_pool(permanent_pool);

      pr_trace_msg(trace_channel, 5, "addr '%s' is an IPv4-mapped IPv6 address",
        pr_netaddr_get_ipstr((pr_netaddr_t *) na1));

      /* This case means that na1 is an IPv4-mapped IPv6 address, and
       * na2 is an IPv4 address.
       */
      a = pr_netaddr_v6tov4(tmp_pool, na1);
      b = (pr_netaddr_t *) na2;

      pr_trace_msg(trace_channel, 6, "comparing IPv4 address '%s' against "
        "IPv4-mapped IPv6 address '%s'", pr_netaddr_get_ipstr(b),
        pr_netaddr_get_ipstr(a));

    } else if (pr_netaddr_is_v4mappedv6(na2) == TRUE) {
      tmp_pool = make_sub_pool(permanent_pool);

      pr_trace_msg(trace_channel, 5, "addr '%s' is an IPv4-mapped IPv6 address",
        pr_netaddr_get_ipstr((pr_netaddr_t *) na2));

      /* This case means that na is an IPv4 address, and na2 is an
       * IPv4-mapped IPv6 address.
       */
      a = (pr_netaddr_t *) na1;
      b = pr_netaddr_v6tov4(tmp_pool, na2);

      pr_trace_msg(trace_channel, 6, "comparing IPv4 address '%s' against "
        "IPv4-mapped IPv6 address '%s'", pr_netaddr_get_ipstr(a),
        pr_netaddr_get_ipstr(b));

    } else {
      a = (pr_netaddr_t *) na1;
      b = (pr_netaddr_t *) na2;
    }

  } else {
    a = (pr_netaddr_t *) na1;
    b = (pr_netaddr_t *) na2;
  }

  switch (pr_netaddr_get_family(a)) {
    case AF_INET:
      res = memcmp(&a->na_addr.v4.sin_addr, &b->na_addr.v4.sin_addr,
        sizeof(struct in_addr));

      if (res != 0) {
        pr_trace_msg(trace_channel, 4, "addr %s does not match addr %s",
          pr_netaddr_get_ipstr(a), pr_netaddr_get_ipstr(b));
      }

      if (tmp_pool) {
        destroy_pool(tmp_pool);
        tmp_pool = NULL;
      }

      return res;

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (use_ipv6) {
        res = memcmp(&a->na_addr.v6.sin6_addr, &b->na_addr.v6.sin6_addr,
          sizeof(struct in6_addr));

        if (res != 0) {
          pr_trace_msg(trace_channel, 4, "addr %s does not match addr %s",
            pr_netaddr_get_ipstr(a), pr_netaddr_get_ipstr(b));
        }

        if (tmp_pool) {
          destroy_pool(tmp_pool);
          tmp_pool = NULL;
        }

        return res;
      }
#endif /* PR_USE_IPV6 */
  }

  if (tmp_pool)
    destroy_pool(tmp_pool);

  errno = EPERM;
  return -1;
}

static int addr_ncmp(const unsigned char *aptr, const unsigned char *bptr,
    unsigned int masklen) {
  unsigned char nbits, nbytes;
  int res;

  /* These null checks are unlikely to happen.  But be prepared, eh? */

  if (aptr != NULL &&
      bptr == NULL) {
    return 1;
  }

  if (aptr == NULL &&
      bptr != NULL) {
    return -1;
  }

  if (aptr == NULL &&
      bptr == NULL) {
    return 0;
  }

  nbytes = masklen / 8;
  nbits = masklen % 8;

  res = memcmp(aptr, bptr, nbytes);
  if (res != 0) {
    return -1;
  }

  if (nbits > 0) {
    unsigned char abyte, bbyte, mask;

    abyte = aptr[nbytes];
    bbyte = bptr[nbytes];

    mask = (0xff << (8 - nbits)) & 0xff;

    if ((abyte & mask) > (bbyte & mask)) {
      return 1;
    }

    if ((abyte & mask) < (bbyte & mask)) {
      return -1;
    }
  }

  return 0;
}

int pr_netaddr_ncmp(const pr_netaddr_t *na1, const pr_netaddr_t *na2,
    unsigned int bitlen) {
  pool *tmp_pool = NULL;
  pr_netaddr_t *a, *b;
  const unsigned char *in1, *in2;
  int res;

  if (na1 != NULL &&
      na2 == NULL) {
    return 1;
  }

  if (na1 == NULL &&
      na2 != NULL) {
    return -1;
  }

  if (na1 == NULL &&
      na2 == NULL) {
    return 0;
  }

  if (pr_netaddr_get_family(na1) != pr_netaddr_get_family(na2)) {

    /* Cannot compare addresses from different families, unless one
     * of the netaddrs has an AF_INET family, and the other has an
     * AF_INET6 family AND is an IPv4-mapped IPv6 address.
     */

    if (pr_netaddr_is_v4mappedv6(na1) != TRUE &&
        pr_netaddr_is_v4mappedv6(na2) != TRUE) {
      errno = EINVAL;
      return -1;
    }

    if (pr_netaddr_is_v4mappedv6(na1) == TRUE) {
      tmp_pool = make_sub_pool(permanent_pool);

      /* This case means that na1 is an IPv4-mapped IPv6 address, and
       * na2 is an IPv4 address.
       */
      a = pr_netaddr_v6tov4(tmp_pool, na1);
      b = (pr_netaddr_t *) na2;

      pr_trace_msg(trace_channel, 6, "comparing IPv4 address '%s' against "
        "IPv4-mapped IPv6 address '%s'", pr_netaddr_get_ipstr(b),
        pr_netaddr_get_ipstr(a));

    } else if (pr_netaddr_is_v4mappedv6(na2) == TRUE) {
      tmp_pool = make_sub_pool(permanent_pool);

      /* This case means that na is an IPv4 address, and na2 is an
       * IPv4-mapped IPv6 address.
       */
      a = (pr_netaddr_t *) na1;
      b = pr_netaddr_v6tov4(tmp_pool, na2);

      pr_trace_msg(trace_channel, 6, "comparing IPv4 address '%s' against "
        "IPv4-mapped IPv6 address '%s'", pr_netaddr_get_ipstr(a),
        pr_netaddr_get_ipstr(b));

    } else {
      a = (pr_netaddr_t *) na1;
      b = (pr_netaddr_t *) na2;
    }

  } else {
    a = (pr_netaddr_t *) na1;
    b = (pr_netaddr_t *) na2;
  }

  switch (pr_netaddr_get_family(a)) {
    case AF_INET: {
      /* Make sure that the given number of bits is not more than supported
       * for IPv4 addresses (32).
       */
      if (bitlen > 32) {
        errno = EINVAL;
        return -1;
      }

      break;
    }

#ifdef PR_USE_IPV6
    case AF_INET6: {
      if (use_ipv6) {
        /* Make sure that the given number of bits is not more than supported
         * for IPv6 addresses (128).
         */
        if (bitlen > 128) {
          errno = EINVAL;
          return -1;
        }

        break;
      }
    }
#endif /* PR_USE_IPV6 */

    default:
      errno = EPERM;
      return -1;
  }

  /* Retrieve pointers to the contained in_addrs. */
  in1 = (const unsigned char *) pr_netaddr_get_inaddr(a);
  in2 = (const unsigned char *) pr_netaddr_get_inaddr(b);

  res = addr_ncmp(in1, in2, bitlen);

  if (tmp_pool) {
    destroy_pool(tmp_pool);
  }

  return res;
}

int pr_netaddr_fnmatch(const pr_netaddr_t *na, const char *pattern, int flags) {

  /* Note: I'm still not sure why proftpd bundles an fnmatch(3)
   * implementation rather than using the system library's implementation.
   * Needs looking into.
   *
   * The FNM_CASEFOLD flag is a GNU extension; perhaps the bundled
   * implementation was added to make that flag available on other platforms.
   */
  int match_flags = PR_FNM_NOESCAPE|PR_FNM_CASEFOLD;

  if (na == NULL ||
      pattern == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (flags & PR_NETADDR_MATCH_DNS) {
    const char *dnsstr;

    dnsstr = pr_netaddr_get_dnsstr(na);
    if (pr_fnmatch(pattern, dnsstr, match_flags) == 0) {
      pr_trace_msg(trace_channel, 6, "DNS name '%s' matches pattern '%s'",
        dnsstr, pattern);
      return TRUE;
    }
  }

  if (flags & PR_NETADDR_MATCH_IP) {
    const char *ipstr;

    ipstr = pr_netaddr_get_ipstr(na);
    if (pr_fnmatch(pattern, ipstr, match_flags) == 0) {
      pr_trace_msg(trace_channel, 6, "IP address '%s' matches pattern '%s'",
        ipstr, pattern);
      return TRUE;
    }

    /* If the address is an IPv4-mapped IPv6 address, get the IPv4 address
     * and try to match that against the configured glob pattern.
     */
    if (pr_netaddr_is_v4mappedv6(na) == TRUE) {
      pool *tmp_pool;
      pr_netaddr_t *a;

      pr_trace_msg(trace_channel, 5, "addr '%s' is an IPv4-mapped IPv6 address",
        ipstr);

      tmp_pool = make_sub_pool(permanent_pool);
      a = pr_netaddr_v6tov4(tmp_pool, na);

      ipstr = pr_netaddr_get_ipstr(a);

      if (pr_fnmatch(pattern, ipstr, match_flags) == 0) {
        pr_trace_msg(trace_channel, 6, "IP address '%s' matches pattern '%s'",
          ipstr, pattern);

        destroy_pool(tmp_pool);
        return TRUE;
      }

      destroy_pool(tmp_pool);
    }
  }

  pr_trace_msg(trace_channel, 4, "addr %s does not match pattern '%s'",
    pr_netaddr_get_ipstr(na), pattern);
  return FALSE;
}

const char *pr_netaddr_get_ipstr(const pr_netaddr_t *na) {
#ifdef PR_USE_IPV6
  char buf[INET6_ADDRSTRLEN];
#else
  char buf[INET_ADDRSTRLEN];
#endif /* PR_USE_IPV6 */
  int res = 0, xerrno;
  pr_netaddr_t *addr;
  
  if (na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* If this pr_netaddr_t has already been resolved to an IP string, return the
   * cached string.
   */
  if (na->na_have_ipstr) {
    return na->na_ipstr;
  }

  memset(buf, '\0', sizeof(buf));
  res = pr_getnameinfo(pr_netaddr_get_sockaddr(na),
    pr_netaddr_get_sockaddr_len(na), buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
  xerrno = errno;

  if (res != 0) {
    if (res != EAI_SYSTEM) {
      pr_log_pri(PR_LOG_WARNING, "getnameinfo error: %s", pr_gai_strerror(res));
      errno = EIO;

    } else {
      pr_log_pri(PR_LOG_WARNING, "getnameinfo system error: [%d] %s",
        xerrno, strerror(xerrno));
      errno = xerrno;
    }

    return NULL;
  }

#ifdef PR_USE_IPV6
  if (use_ipv6 &&
      pr_netaddr_get_family(na) == AF_INET6) {
    /* The getnameinfo(3) implementation might append the zone ID to an IPv6
     * name; we need to trim it off.
     */
    char *ptr;

    ptr = strrchr(buf, '%');
    if (ptr != NULL) {
      *ptr = '\0';
    }
  }
#endif /* PR_USE_IPV6 */

  /* Copy the string into the pr_netaddr_t cache as well, so we only
   * have to do this once for this pr_netaddr_t.  But to do this, we need
   * let the compiler know that the pr_netaddr_t is not really const at this
   * point.
   */
  addr = (pr_netaddr_t *) na;
  memset(addr->na_ipstr, '\0', sizeof(addr->na_ipstr));
  sstrncpy(addr->na_ipstr, buf, sizeof(addr->na_ipstr));
  addr->na_have_ipstr = TRUE;

  return na->na_ipstr;
}

#if defined(HAVE_GETADDRINFO) && !defined(HAVE_GETHOSTBYNAME2)
static int netaddr_get_dnsstr_getaddrinfo(const pr_netaddr_t *na,
    const char *name) {
  struct addrinfo hints, *info = NULL;
  int family, flags = 0, res = 0, ok = FALSE;
  void *inaddr = pr_netaddr_get_inaddr(na);

  family = pr_netaddr_get_family(na);
  if (pr_netaddr_is_v4mappedv6(na) == TRUE) {
    family = AF_INET;
    inaddr = get_v4inaddr(na);
  }

#ifdef AI_CANONNAME
  flags |= AI_CANONNAME;
#endif

#ifdef AI_ALL
  flags |= AI_ALL;
#endif

#ifdef AI_V4MAPPED
  flags |= AI_V4MAPPED;
#endif

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = flags;

  res = pr_getaddrinfo(name, NULL, &hints, &info);
  if (res != 0) {
    int xerrno = errno;

    if (res != EAI_SYSTEM) {
      pr_trace_msg(trace_channel, 1, "%s getaddrinfo '%s' error: %s",
        hints.ai_family == AF_INET ? "IPv4" : "IPv6", name,
        pr_gai_strerror(res));

    } else {
      pr_trace_msg(trace_channel, 1,
        "%s getaddrinfo '%s' system error: [%d] %s",
        hints.ai_family == AF_INET ? "IPv4" : "IPv6", name, xerrno,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  if (info != NULL) {
#ifdef PR_USE_IPV6
    char buf[INET6_ADDRSTRLEN];
#else
    char buf[INET_ADDRSTRLEN];
#endif /* PR_USE_IPV6 */
    struct addrinfo *ai;
    int xerrno;

    memset(buf, '\0', sizeof(buf));
    res = pr_getnameinfo(info->ai_addr, info->ai_addrlen, buf, sizeof(buf),
      NULL, 0, NI_NAMEREQD);
    xerrno = errno;

    if (res != 0) {
      if (res != EAI_SYSTEM) {
        pr_trace_msg(trace_channel, 1, "%s getnameinfo error: %s",
          hints.ai_family == AF_INET ? "IPv4" : "IPv6", pr_gai_strerror(res));

      } else {
        pr_trace_msg(trace_channel, 1,
          "%s getnameinfo system error: [%d] %s",
          hints.ai_family == AF_INET ? "IPv4" : "IPv6", xerrno,
          strerror(xerrno));
      }

      errno = xerrno;
      return -1;
    }

    netaddr_dnscache_set(pr_netaddr_get_ipstr(na), buf);
    ok = TRUE;

    pr_trace_msg(trace_channel, 10,
      "checking addresses associated with host '%s'", buf);

    for (ai = info->ai_next; ai; ai = ai->ai_next) {
#ifdef PR_USE_IPV6
      char alias[INET6_ADDRSTRLEN];
#else
      char alias[INET_ADDRSTRLEN];
#endif /* PR_USE_IPV6 */

      switch (ai->ai_family) {
        case AF_INET:
          if (family == AF_INET) {
            if (memcmp(ai->ai_addr, inaddr, ai->ai_addrlen) == 0) {
              memset(alias, '\0', sizeof(alias));
              res = pr_getnameinfo(ai->ai_addr, ai->ai_addrlen, alias,
                sizeof(alias), NULL, 0, NI_NAMEREQD);
              if (res == 0) {
                pr_trace_msg(trace_channel, 10,
                  "host '%s' has alias '%s'", buf, alias);
                netaddr_ipcache_set(alias, na);
                netaddr_dnscache_set(pr_netaddr_get_ipstr(na), alias);
              }
            }
          }
          break;

#ifdef PR_USE_IPV6
        case AF_INET6:
          if (use_ipv6 && family == AF_INET6) {
            if (memcmp(ai->ai_addr, inaddr, ai->ai_addrlen) == 0) {
              memset(alias, '\0', sizeof(alias));
              res = pr_getnameinfo(ai->ai_addr, ai->ai_addrlen, alias,
                sizeof(alias), NULL, 0, NI_NAMEREQD);
              if (res == 0) {
                pr_trace_msg(trace_channel, 10,
                  "host '%s' has alias '%s'", buf, alias);
                netaddr_ipcache_set(alias, na);
                netaddr_dnscache_set(pr_netaddr_get_ipstr(na), alias);
              }
            }
          }
          break;
#endif /* PR_USE_IPV6 */
      }
    }

    pr_freeaddrinfo(info);
  }

  return (ok ? 0 : -1);
}
#endif /* HAVE_GETADDRINFO and not HAVE_GETHOSTBYNAME2 */

#ifdef HAVE_GETHOSTBYNAME2
static int netaddr_get_dnsstr_gethostbyname(const pr_netaddr_t *na,
    const char *name) {
  char **checkaddr;
  struct hostent *hent = NULL;
  int family, ok = FALSE;
  void *inaddr;

  family = pr_netaddr_get_family(na);
  if (family < 0) {
    return -1;
  }

  inaddr = pr_netaddr_get_inaddr(na);

  if (pr_netaddr_is_v4mappedv6(na) == TRUE) {
    family = AF_INET;
    inaddr = get_v4inaddr(na);
  }

  hent = gethostbyname2(name, family);

  if (hent != NULL) {
    if (hent->h_name != NULL) {
      netaddr_dnscache_set(pr_netaddr_get_ipstr(na), hent->h_name);
    }

    pr_trace_msg(trace_channel, 10,
      "checking addresses associated with host '%s'",
      hent->h_name ? hent->h_name : "(null)");

    switch (hent->h_addrtype) {
      case AF_INET:
        if (family == AF_INET) {
          for (checkaddr = hent->h_addr_list; *checkaddr; ++checkaddr) {
            if (memcmp(*checkaddr, inaddr, hent->h_length) == 0) {
              char **alias;

              for (alias = hent->h_aliases; *alias; ++alias) {
                if (hent->h_name) {
                  pr_trace_msg(trace_channel, 10,
                    "host '%s' has alias '%s'", hent->h_name, *alias);
                  netaddr_ipcache_set(*alias, na);
                  netaddr_dnscache_set(pr_netaddr_get_ipstr(na), *alias);
                }
              }

              ok = TRUE;
              break;
            }
          }
        } 
        break;

# ifdef PR_USE_IPV6
      case AF_INET6:
        if (use_ipv6 && family == AF_INET6) {
          for (checkaddr = hent->h_addr_list; *checkaddr; ++checkaddr) {
            if (memcmp(*checkaddr, inaddr, hent->h_length) == 0) {
              char **alias;

              for (alias = hent->h_aliases; *alias; ++alias) {
                if (hent->h_name) {
                  pr_trace_msg(trace_channel, 10,
                    "host '%s' has alias '%s'", hent->h_name, *alias);
                  netaddr_ipcache_set(*alias, na);
                  netaddr_dnscache_set(pr_netaddr_get_ipstr(na), *alias);
                }
              }

              ok = TRUE;
              break;
            }
          }
        } 
        break;
# endif /* PR_USE_IPV6 */
    }

  } else {
    pr_log_debug(DEBUG1, "notice: unable to resolve '%s' as %s address: %s",
      name, family != AF_INET ? "IPv6" : "IPv4", hstrerror(h_errno));
  }

  return (ok ? 0 : -1);
}
#endif /* HAVE_GETHOSTBYNAME2 */

/* This differs from pr_netaddr_get_ipstr() in that pr_netaddr_get_ipstr()
 * returns a string of the numeric form of the given network address, whereas
 * this function returns a string of the DNS name (if present).
 */
const char *pr_netaddr_get_dnsstr(const pr_netaddr_t *na) {
  char dns_buf[1024], *name = NULL;
  pr_netaddr_t *addr = NULL, *cache = NULL;

  if (na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  cache = netaddr_ipcache_get(NULL, pr_netaddr_get_ipstr(na));
  if (cache &&
      cache->na_have_dnsstr) {
    addr = (pr_netaddr_t *) na;
    memset(addr->na_dnsstr, '\0', sizeof(addr->na_dnsstr));
    sstrncpy(addr->na_dnsstr, cache->na_dnsstr, sizeof(addr->na_dnsstr));
    addr->na_have_dnsstr = TRUE;

    return na->na_dnsstr;
  }

  /* If this pr_netaddr_t has already been resolved to an DNS string, return the
   * cached string.
   */
  if (na->na_have_dnsstr) {
    return na->na_dnsstr;
  }

  if (reverse_dns) {
    int res = 0;

    pr_trace_msg(trace_channel, 3,
      "verifying DNS name for IP address %s via reverse DNS lookup",
      pr_netaddr_get_ipstr(na));

    memset(dns_buf, '\0', sizeof(dns_buf));
    res = pr_getnameinfo(pr_netaddr_get_sockaddr(na),
      pr_netaddr_get_sockaddr_len(na), dns_buf, sizeof(dns_buf), NULL, 0,
      NI_NAMEREQD);
    dns_buf[sizeof(dns_buf)-1] = '\0';

    if (res == 0) {
      /* Some older glibc's getaddrinfo(3) does not appear to handle IPv6
       * addresses properly; we thus prefer gethostbyname2(3) on systems
       * which have it, for such older systems.
       */
#ifdef HAVE_GETHOSTBYNAME2
      res = netaddr_get_dnsstr_gethostbyname(na, dns_buf);
#else
      res = netaddr_get_dnsstr_getaddrinfo(na, dns_buf);
#endif /* HAVE_GETHOSTBYNAME2 */
      if (res == 0) {
        name = dns_buf;
        pr_trace_msg(trace_channel, 8,
          "using DNS name '%s' for IP address '%s'", name,
          pr_netaddr_get_ipstr(na));

      } else {
        name = NULL;
        pr_trace_msg(trace_channel, 8,
          "unable to verify any DNS names for IP address '%s'",
          pr_netaddr_get_ipstr(na));
      }
    }

  } else {
    pr_log_debug(DEBUG10,
      "UseReverseDNS off, returning IP address instead of DNS name");
  }

  if (name) {
    name = pr_netaddr_validate_dns_str(name);

  } else {
    name = (char *) pr_netaddr_get_ipstr(na);
  }

  /* Copy the string into the pr_netaddr_t cache as well, so we only
   * have to do this once for this pr_netaddr_t.  But to do this, we need
   * let the compiler know that the pr_netaddr_t is not really const at this
   * point.
   */
  addr = (pr_netaddr_t *) na;
  memset(addr->na_dnsstr, '\0', sizeof(addr->na_dnsstr));
  sstrncpy(addr->na_dnsstr, name, sizeof(addr->na_dnsstr));
  addr->na_have_dnsstr = TRUE;

  /* Update the netaddr object in the cache with the resolved DNS names. */
  netaddr_ipcache_set(name, na);
  netaddr_ipcache_set(pr_netaddr_get_ipstr(na), na);

  return na->na_dnsstr;
}

array_header *pr_netaddr_get_dnsstr_list(pool *p, const pr_netaddr_t *na) {
  array_header *res;

  if (p == NULL ||
      na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (!reverse_dns) {
    /* If UseReverseDNS is off, then we won't have any names that we trust.
     * So return an empty list.
     */
    return make_array(p, 0, sizeof(char *));
  }

  res = netaddr_dnscache_get(p, pr_netaddr_get_ipstr(na));
  if (res == NULL) {
    res = make_array(p, 0, sizeof(char *));
  }

  return res;
}

/* Return the hostname (wrapper for gethostname(2), except returns FQDN). */
const char *pr_netaddr_get_localaddr_str(pool *p) {
  char buf[256];
  int res, xerrno;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (have_localaddr_str) {
    return pr_netaddr_validate_dns_str(pstrdup(p, localaddr_str));
  }

  memset(buf, '\0', sizeof(buf));
  res = gethostname(buf, sizeof(buf)-1);
  xerrno = errno;

  if (res >= 0) {
    struct hostent *host;

    buf[sizeof(buf)-1] = '\0';

    /* Note: this may need to be gethostbyname2() on systems that provide
     * that function, for it is possible that the configured hostname for
     * a machine only resolves to an IPv6 address.
     */
#ifdef HAVE_GETHOSTBYNAME2
    host = gethostbyname2(buf, AF_INET);
    if (host == NULL &&
        h_errno == HOST_NOT_FOUND) {
# ifdef AF_INET6
      host = gethostbyname2(buf, AF_INET6);
# endif /* AF_INET6 */
    }
#else
    host = gethostbyname(buf);
#endif
    if (host != NULL) {
      return pr_netaddr_validate_dns_str(pstrdup(p, host->h_name));
    }

    pr_trace_msg(trace_channel, 14,
      "gethostbyname() failed for '%s': %s", buf, hstrerror(h_errno));
    return pr_netaddr_validate_dns_str(pstrdup(p, buf));
  }

  pr_trace_msg(trace_channel, 1, "gethostname(2) error: %s", strerror(xerrno));
  errno = xerrno;
  return NULL;
}

int pr_netaddr_set_localaddr_str(const char *addr_str) {
  if (addr_str == NULL) {
    errno = EINVAL;
    return -1;
  }

  memset(localaddr_str, '\0', sizeof(localaddr_str));
  sstrncpy(localaddr_str, addr_str, sizeof(localaddr_str));
  have_localaddr_str = TRUE;
  return 0;
}

int pr_netaddr_is_loopback(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return IN_IS_ADDR_LOOPBACK(
        (struct in_addr *) pr_netaddr_get_inaddr(na));

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (pr_netaddr_is_v4mappedv6(na) == TRUE) {
        pool *tmp_pool;
        pr_netaddr_t *v4na;
        int res;

        tmp_pool = make_sub_pool(permanent_pool);
        v4na = pr_netaddr_v6tov4(tmp_pool, na);

        res = pr_netaddr_is_loopback(v4na);
        destroy_pool(tmp_pool);

        return res;
      }

      /* XXX *sigh* Different platforms implement the IN6_IS_ADDR macros
       * differently.  For example, on Linux, those macros expect to operate
       * on s6_addr32, while on Solaris, the macros operate on struct in6_addr.
       * Certain Drafts define the macros to work on struct in6_addr *, as
       * Solaris does, so Linux may have it wrong.  Tentative research on
       * Google shows some BSD netinet6/in6.h headers that define these
       * macros in terms of struct in6_addr *, so I'll go with that for now.
       * Joy. =P
       */
# ifndef LINUX
      return IN6_IS_ADDR_LOOPBACK(
        (struct in6_addr *) pr_netaddr_get_inaddr(na));
# else
      return IN6_IS_ADDR_LOOPBACK(
        ((struct in6_addr *) pr_netaddr_get_inaddr(na))->s6_addr32);
# endif
#endif /* PR_USE_IPV6 */
  }

  return FALSE;
}

/* RFC 1918 addresses:
 * 
 * 10.0.0.0 - 10.255.255.255 (10.0.0.0/8, 24-bit block)
 * 172.16.0.0 - 172.31.255.255 (172.16.0.0/12, 20-bit block)
 * 192.168.0.0 - 192.168.255.255 (192.168.0.0/16, 16-bit block)
 * 
 */

static int is_10_xxx_addr(uint32_t addrno) {
  uint32_t rfc1918_addrno;

  rfc1918_addrno = htonl(0x0a000000);
  return addr_ncmp((const unsigned char *) &addrno,
    (const unsigned char *) &rfc1918_addrno, 8);
}

static int is_172_16_xx_addr(uint32_t addrno) {
  uint32_t rfc1918_addrno;

  rfc1918_addrno = htonl(0xac100000);
  return addr_ncmp((const unsigned char *) &addrno,
    (const unsigned char *) &rfc1918_addrno, 12);
}

static int is_192_168_xx_addr(uint32_t addrno) {
  uint32_t rfc1918_addrno;

  rfc1918_addrno = htonl(0xc0a80000);
  return addr_ncmp((const unsigned char *) &addrno,
    (const unsigned char *) &rfc1918_addrno, 16);
}

int pr_netaddr_is_rfc1918(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET: {
      uint32_t addrno;

      addrno = pr_netaddr_get_addrno(na);
      if (is_192_168_xx_addr(addrno) == 0 ||
          is_172_16_xx_addr(addrno) == 0 ||
          is_10_xxx_addr(addrno) == 0) {
          return TRUE;
      }
      break;
    }

#ifdef PR_USE_IPV6
    case AF_INET6:
      if (pr_netaddr_is_v4mappedv6(na) == TRUE) {
        pool *tmp_pool;
        pr_netaddr_t *v4na;
        int res;

        tmp_pool = make_sub_pool(permanent_pool);
        v4na = pr_netaddr_v6tov4(tmp_pool, na);

        res = pr_netaddr_is_rfc1918(v4na);
        destroy_pool(tmp_pool);

        return res;
      }

      /* By definition, an IPv6 address is not an RFC1918-defined address. */
      return FALSE;
#endif /* PR_USE_IPV6 */
  }

  errno = EINVAL;
  return FALSE;
}

/* A slightly naughty function that should go away. It relies too much on
 * knowledge of the internal structures of struct in_addr, struct in6_addr.
 */
uint32_t pr_netaddr_get_addrno(const pr_netaddr_t *na) {
  if (na == NULL) {
    errno = EINVAL;
    return 0;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:
      return (uint32_t) na->na_addr.v4.sin_addr.s_addr;

#ifdef PR_USE_IPV6
    case AF_INET6: {

      /* Linux defines s6_addr32 in its netinet/in.h header.
       * FreeBSD defines s6_addr32 in KAME's netinet6/in6.h header.
       * Solaris defines s6_addr32 in its netinet/in.h header, but only
       * for kernel builds.
       */
#if 0
      int *addrs = ((struct sockaddr_in6 *) pr_netaddr_get_inaddr(na))->s6_addr32;
      return addrs[0];
#else
      errno = ENOENT;
      return 0;
#endif
    }
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return 0;
}

int pr_netaddr_is_v4(const char *name) {
  int res;
  struct sockaddr_in v4;

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  memset(&v4, 0, sizeof(v4));
  v4.sin_family = AF_INET;

# ifdef SIN_LEN
  v4.sin_len = sizeof(struct sockaddr_in);
# endif /* SIN_LEN */

  res = pr_inet_pton(AF_INET, name, &v4.sin_addr);
  if (res > 0) {
    return TRUE;
  }

  return FALSE;
}

int pr_netaddr_is_v6(const char *name) {
  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef PR_USE_IPV6
  if (use_ipv6) {
    int res;
    struct sockaddr_in6 v6;

    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;

# ifdef SIN6_LEN
    v6.sin6_len = sizeof(struct sockaddr_in6);
# endif /* SIN6_LEN */

    res = pr_inet_pton(AF_INET6, name, &v6.sin6_addr);
    if (res > 0) {
      return TRUE;
    }
  }

  return FALSE;
#else
  return FALSE;
#endif /* !PR_USE_IPV6 */
}

int pr_netaddr_is_v4mappedv6(const pr_netaddr_t *na) {
  if (!na) {
    errno = EINVAL;
    return -1;
  }

  switch (pr_netaddr_get_family(na)) {
    case AF_INET:

      /* This function tests only IPv6 addresses, not IPv4 addresses. */
      errno = EINVAL;
      return -1;

#ifdef PR_USE_IPV6
    case AF_INET6: {
      int res;

      if (!use_ipv6) {
        errno = EINVAL;
        return -1;
      }

# ifndef LINUX
      res = IN6_IS_ADDR_V4MAPPED(
        (struct in6_addr *) pr_netaddr_get_inaddr(na));
# else
      res = IN6_IS_ADDR_V4MAPPED(
        ((struct in6_addr *) pr_netaddr_get_inaddr(na))->s6_addr32);
# endif

      if (res != TRUE) {
        errno = EINVAL;
      }

      return res;
    }
#endif /* PR_USE_IPV6 */
  }

  errno = EPERM;
  return -1;
}

pr_netaddr_t *pr_netaddr_v6tov4(pool *p, const pr_netaddr_t *na) {
  pr_netaddr_t *res;

  if (p == NULL ||
      na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (pr_netaddr_is_v4mappedv6(na) != TRUE) {
    errno = EPERM;
    return NULL;
  }

  res = pr_netaddr_alloc(p);
  pr_netaddr_set_family(res, AF_INET);
  pr_netaddr_set_port(res, pr_netaddr_get_port(na));
  memcpy(&res->na_addr.v4.sin_addr, get_v4inaddr(na), sizeof(struct in_addr));

  return res;
}

pr_netaddr_t *pr_netaddr_v4tov6(pool *p, const pr_netaddr_t *na) {
  pr_netaddr_t *res;

  if (p == NULL ||
      na == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (pr_netaddr_get_family(na) != AF_INET) {
    errno = EPERM;
    return NULL;
  }

#ifdef PR_USE_IPV6
  res = (pr_netaddr_t *) pr_netaddr_get_addr(p,
    pstrcat(p, "::ffff:", pr_netaddr_get_ipstr(na), NULL), NULL);
  if (res != NULL) {
    pr_netaddr_set_port(res, pr_netaddr_get_port(na));
  }

#else
  errno = EPERM;
  res = NULL;
#endif /* PR_USE_IPV6 */

  return res;
}

const pr_netaddr_t *pr_netaddr_get_sess_local_addr(void) {
  if (have_sess_local_addr) {
    return &sess_local_addr;
  }

  errno = ENOENT;
  return NULL;
}

const pr_netaddr_t *pr_netaddr_get_sess_remote_addr(void) {
  if (have_sess_remote_addr) {
    return &sess_remote_addr;
  }

  errno = ENOENT;
  return NULL;
}

const char *pr_netaddr_get_sess_remote_name(void) {
  if (have_sess_remote_addr) {
    return sess_remote_name;
  }

  errno = ENOENT;
  return NULL;
}

void pr_netaddr_set_sess_addrs(void) {
  memset(&sess_local_addr, 0, sizeof(sess_local_addr));
  pr_netaddr_set_family(&sess_local_addr,
    pr_netaddr_get_family(session.c->local_addr));
  pr_netaddr_set_sockaddr(&sess_local_addr,
    pr_netaddr_get_sockaddr(session.c->local_addr));
  have_sess_local_addr = TRUE;

  memset(&sess_remote_addr, 0, sizeof(sess_remote_addr));
  pr_netaddr_set_family(&sess_remote_addr,
    pr_netaddr_get_family(session.c->remote_addr));
  pr_netaddr_set_sockaddr(&sess_remote_addr,
    pr_netaddr_get_sockaddr(session.c->remote_addr));

  memset(sess_remote_name, '\0', sizeof(sess_remote_name));
  sstrncpy(sess_remote_name, session.c->remote_name, sizeof(sess_remote_name));
  have_sess_remote_addr = TRUE;
}

unsigned char pr_netaddr_use_ipv6(void) {
  if (use_ipv6)
    return TRUE;

  return FALSE;
}

void pr_netaddr_disable_ipv6(void) {
#ifdef PR_USE_IPV6
  use_ipv6 = 0;
#endif /* PR_USE_IPV6 */
}

void pr_netaddr_enable_ipv6(void) {
#ifdef PR_USE_IPV6
  use_ipv6 = 1;
#endif /* PR_USE_IPV6 */
}

void pr_netaddr_clear_cache(void) {
  if (netaddr_iptab) {
    pr_trace_msg(trace_channel, 5, "emptying netaddr IP cache");
    (void) pr_table_empty(netaddr_iptab);
    (void) pr_table_free(netaddr_iptab);

    /* Allocate a fresh table. */
    netaddr_iptab = pr_table_alloc(netaddr_pool, 0);
  }

  if (netaddr_dnstab) {
    pr_trace_msg(trace_channel, 5, "emptying netaddr DNS cache");
    (void) pr_table_empty(netaddr_dnstab);
    (void) pr_table_free(netaddr_dnstab);

    /* Allocate a fresh table. */
    netaddr_dnstab = pr_table_alloc(netaddr_pool, 0);
  }
}

void pr_netaddr_clear_dnscache(const char *ip_str) {
  if (netaddr_dnstab != NULL) {
    (void) pr_table_remove(netaddr_dnstab, ip_str, NULL);
  }
}

void pr_netaddr_clear_ipcache(const char *name) {
  if (netaddr_iptab != NULL) {
    (void) pr_table_remove(netaddr_iptab, name, NULL);
  }
}

void init_netaddr(void) {
  if (netaddr_pool) {
    pr_netaddr_clear_cache();
    destroy_pool(netaddr_pool);
    netaddr_pool = NULL;
  }

  netaddr_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(netaddr_pool, "Netaddr API");

  netaddr_iptab = pr_table_alloc(netaddr_pool, 0);
  netaddr_dnstab = pr_table_alloc(netaddr_pool, 0);
}
