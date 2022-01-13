/*
 * ProFTPD - mod_sftp traffic analysis protection
 * Copyright (c) 2008-2016 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_sftp.h"
#include "ssh2.h"
#include "packet.h"
#include "msg.h"
#include "tap.h"
#include "interop.h"

extern module sftp_module;

static pool *tap_pool = NULL;
static int tap_timerno = -1;

static const char *trace_channel = "ssh2";

struct sftp_tap_policy {
  const char *policy;

  unsigned int chance_max;
  unsigned int chance;
  unsigned int min_datalen;
  unsigned int max_datalen;

  int check_interval;
  unsigned long min_secs;
  unsigned long max_secs;
};

static struct sftp_tap_policy tap_policies[] = {
  { "none",	0,	0,	0,	0,	0,	0,	0 },
  { "low",	1000,	0,	64,	256,	5,	15,	300 },
  { "medium",	100,	0,	32,	768,	5,	10,	60 },
  { "high",	10,	0,	16,	2048,	1,	5,	15 },
  { "paranoid",	1,	0,	0,	0,	1,	1,	5 },
  { "rogaway", 	1,	0,	64,	256,	0,	0,	0 },
  { NULL,	0,	0,	0,	0,	0,	0,	0 }
};

static struct sftp_tap_policy curr_policy = { NULL, 0, 0, 0, 0, 0, 0, 0 };

/* This only checks whether to TRY to send a TAP packet; it does not force
 * a TAP packet to be sent.  The request to send a TAP packet, if we try,
 * is still subject to the 1-in-N chance of sending a packet as set by
 * the selected policy.
 */
static int check_packet_times_cb(CALLBACK_FRAME) {
  time_t last_recvd, last_sent, now;
  unsigned long since_recvd, since_sent;
  unsigned int chance;
  int rnd;

  /* Always return 1 so that this timer is rescheduled. */

  sftp_ssh2_packet_get_last_recvd(&last_recvd);
  sftp_ssh2_packet_get_last_sent(&last_sent);
  time(&now);

  since_recvd = now - last_recvd;
  since_sent = now - last_sent;

  /* If it's been less than min_secs, do NOT send a packet. */
  if (since_recvd <= curr_policy.min_secs &&
      since_sent <= curr_policy.max_secs) {
    return 1;
  }

  /* If it's been more than max_secs, DO attempt send a packet. */
  if (since_recvd >= curr_policy.max_secs &&
      since_sent >= curr_policy.max_secs) {
    pr_trace_msg(trace_channel, 15, "too much inactivity, attempting "
      "to send TAP packet");

    if (sftp_tap_send_packet() < 0) {
      pr_trace_msg(trace_channel, 3, "error sending TAP packet: %s",
        strerror(errno));
    }

    return 1;
  }

  /* Otherwise, pick a random number, see if it's time to send a packet. */
  if (curr_policy.chance_max != 1) {
    rnd = (int) (rand() / (RAND_MAX / curr_policy.chance_max + 1));

  } else {
    rnd = 1;
  }

  chance = rnd;
  if (chance == curr_policy.chance) {
    pr_trace_msg(trace_channel, 15, "perhaps too inactive, attempting to send "
      "a TAP packet");

    if (sftp_tap_send_packet() < 0) {
      pr_trace_msg(trace_channel, 3, "error sending TAP packet: %s",
        strerror(errno));
    }

    return 1;
  }

  return 1;
}

static void copy_policy(struct sftp_tap_policy *dst,
  struct sftp_tap_policy *src) {

  dst->policy = src->policy;
  dst->chance_max = src->chance_max;
  dst->min_datalen = src->min_datalen;
  dst->max_datalen = src->max_datalen;
}

static void set_policy_chance(struct sftp_tap_policy *policy) {
  if (policy->chance_max == 0) {
    /* This is the 'none' policy; no need to do anything. */
    return;
  }

  if (policy->chance_max != 1) {
    policy->chance = (int) (rand() / (RAND_MAX / policy->chance_max + 1));

  } else {
    policy->chance = 1;
  }
}

static void set_policy_timer(struct sftp_tap_policy *policy) {

  /* Start a timer which checks the last times we received and sent packets.
   * From there, we may want to inject a TAP message, depending on the
   * policy.
   */
  if (policy->check_interval > 0) {
    tap_timerno = pr_timer_add(policy->check_interval, -1,
      &sftp_module, check_packet_times_cb, "SFTP TAP check");
  }
}

int sftp_tap_have_policy(const char *policy) {
  register unsigned int i;

  for (i = 0; tap_policies[i].policy; i++) {
    if (strcasecmp(tap_policies[i].policy, policy) == 0) {
      return 0;
    }
  }

  errno = ENOENT;
  return -1;
}

int sftp_tap_send_packet(void) {
  int rnd;
  unsigned int chance;

  if (!sftp_interop_supports_feature(SFTP_SSH2_FEAT_IGNORE_MSG)) {
    pr_trace_msg(trace_channel, 3,
      "unable to send TAP packet: IGNORE not supported by client");
    return 0;
  }

  if (curr_policy.chance_max == 0) {
    /* The "none" policy is in effect; nothing to do. */
    return 0;
  }

  /* Calculate our odds of sending a tap packet, based on the configured
   * policy.
   */
  if (curr_policy.chance_max != 1) {
    rnd = (int) (rand() / (RAND_MAX / curr_policy.chance_max + 1));

  } else {
    rnd = 1;
  }

  chance = rnd;
  if (chance == curr_policy.chance) {
    unsigned char *buf, *ptr, *rand_data;
    uint32_t bufsz, buflen, rand_datalen;
    struct ssh2_packet *pkt;
    unsigned int max_datalen = 8192;

    if (curr_policy.max_datalen) {
      max_datalen = curr_policy.max_datalen;
    }

    rand_datalen = (uint32_t) (curr_policy.min_datalen + rand() /
      (RAND_MAX / (max_datalen - curr_policy.min_datalen) + 1));

    pr_trace_msg(trace_channel, 20,  "sending random SSH2_MSG_IGNORE message "
      "(%lu bytes) based on '%s' TAP policy", (unsigned long) rand_datalen,
      curr_policy.policy);

    pkt = sftp_ssh2_packet_create(tap_pool);
    bufsz = buflen = rand_datalen + 32;
    ptr = buf = palloc(pkt->pool, bufsz);

    rand_data = palloc(pkt->pool, rand_datalen);

    RAND_bytes(rand_data, rand_datalen);

    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_IGNORE);
    sftp_msg_write_data(&buf, &buflen, rand_data, rand_datalen, TRUE);

    pkt->payload = ptr;
    pkt->payload_len = (bufsz - buflen);

    if (sftp_ssh2_packet_send(sftp_conn->wfd, pkt) < 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 12,
        "error writing TAP packet: %s", strerror(xerrno));
    }

    destroy_pool(pkt->pool);
  }
 
  return 0;
}

int sftp_tap_set_policy(const char *policy) {
  register unsigned int i;

  if (tap_pool) {

    /* Special case: IFF the existing policy is 'none' AND the given
     * policy is 'rogaway', just return.  The 'none' policy must have been
     * explicitly configured, and it should override the automatic use of
     * the 'rogaway' policy.
     */
    if (strncmp(curr_policy.policy, "none", 5) == 0 &&
        strncasecmp(policy, "rogaway", 8) == 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "'none' traffic policy explicitly configured, ignoring '%s' policy",
        policy);
      return 0;
    }

    destroy_pool(tap_pool);

    if (tap_timerno > 0) {
      pr_timer_remove(tap_timerno, &sftp_module);
      tap_timerno = -1;
    }
  }

  tap_pool = make_sub_pool(sftp_pool);
  pr_pool_tag(tap_pool, "SFTP TAP Pool");

  memset(&curr_policy, 0, sizeof(struct sftp_tap_policy));

  for (i = 0; tap_policies[i].policy; i++) {
    if (strcasecmp(tap_policies[i].policy, policy) == 0) {
      copy_policy(&curr_policy, &(tap_policies[i]));
      set_policy_chance(&curr_policy);
      set_policy_timer(&curr_policy);
      return 0;
    }
  }

  errno = ENOENT;
  return -1;
}
