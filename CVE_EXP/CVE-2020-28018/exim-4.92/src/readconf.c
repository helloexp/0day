/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for reading the configuration file, and for displaying
overall configuration values. Thanks to Brian Candler for the original
implementation of the conditional .ifdef etc. */

#include "exim.h"

#ifdef MACRO_PREDEF
# include "macro_predef.h"
#endif

#define READCONF_DEBUG	if (FALSE)	/* Change to TRUE to enable */


static uschar * syslog_facility_str;
static void fn_smtp_receive_timeout(const uschar *, const uschar *);

/*************************************************
*           Main configuration options           *
*************************************************/

/* The list of options that can be set in the main configuration file. This
must be in alphabetic order because it is searched by binary chop. */

static optionlist optionlist_config[] = {
  { "*set_exim_group",          opt_bool|opt_hidden, &exim_gid_set },
  { "*set_exim_user",           opt_bool|opt_hidden, &exim_uid_set },
  { "*set_system_filter_group", opt_bool|opt_hidden, &system_filter_gid_set },
  { "*set_system_filter_user",  opt_bool|opt_hidden, &system_filter_uid_set },
  { "accept_8bitmime",          opt_bool,        &accept_8bitmime },
  { "acl_not_smtp",             opt_stringptr,   &acl_not_smtp },
#ifdef WITH_CONTENT_SCAN
  { "acl_not_smtp_mime",        opt_stringptr,   &acl_not_smtp_mime },
#endif
  { "acl_not_smtp_start",       opt_stringptr,   &acl_not_smtp_start },
  { "acl_smtp_auth",            opt_stringptr,   &acl_smtp_auth },
  { "acl_smtp_connect",         opt_stringptr,   &acl_smtp_connect },
  { "acl_smtp_data",            opt_stringptr,   &acl_smtp_data },
#ifndef DISABLE_PRDR
  { "acl_smtp_data_prdr",       opt_stringptr,   &acl_smtp_data_prdr },
#endif
#ifndef DISABLE_DKIM
  { "acl_smtp_dkim",            opt_stringptr,   &acl_smtp_dkim },
#endif
  { "acl_smtp_etrn",            opt_stringptr,   &acl_smtp_etrn },
  { "acl_smtp_expn",            opt_stringptr,   &acl_smtp_expn },
  { "acl_smtp_helo",            opt_stringptr,   &acl_smtp_helo },
  { "acl_smtp_mail",            opt_stringptr,   &acl_smtp_mail },
  { "acl_smtp_mailauth",        opt_stringptr,   &acl_smtp_mailauth },
#ifdef WITH_CONTENT_SCAN
  { "acl_smtp_mime",            opt_stringptr,   &acl_smtp_mime },
#endif
  { "acl_smtp_notquit",         opt_stringptr,   &acl_smtp_notquit },
  { "acl_smtp_predata",         opt_stringptr,   &acl_smtp_predata },
  { "acl_smtp_quit",            opt_stringptr,   &acl_smtp_quit },
  { "acl_smtp_rcpt",            opt_stringptr,   &acl_smtp_rcpt },
#ifdef SUPPORT_TLS
  { "acl_smtp_starttls",        opt_stringptr,   &acl_smtp_starttls },
#endif
  { "acl_smtp_vrfy",            opt_stringptr,   &acl_smtp_vrfy },
  { "add_environment",          opt_stringptr,   &add_environment },
  { "admin_groups",             opt_gidlist,     &admin_groups },
  { "allow_domain_literals",    opt_bool,        &allow_domain_literals },
  { "allow_mx_to_ip",           opt_bool,        &allow_mx_to_ip },
  { "allow_utf8_domains",       opt_bool,        &allow_utf8_domains },
  { "auth_advertise_hosts",     opt_stringptr,   &auth_advertise_hosts },
  { "auto_thaw",                opt_time,        &auto_thaw },
#ifdef WITH_CONTENT_SCAN
  { "av_scanner",               opt_stringptr,   &av_scanner },
#endif
  { "bi_command",               opt_stringptr,   &bi_command },
#ifdef EXPERIMENTAL_BRIGHTMAIL
  { "bmi_config_file",          opt_stringptr,   &bmi_config_file },
#endif
  { "bounce_message_file",      opt_stringptr,   &bounce_message_file },
  { "bounce_message_text",      opt_stringptr,   &bounce_message_text },
  { "bounce_return_body",       opt_bool,        &bounce_return_body },
  { "bounce_return_linesize_limit", opt_mkint,   &bounce_return_linesize_limit },
  { "bounce_return_message",    opt_bool,        &bounce_return_message },
  { "bounce_return_size_limit", opt_mkint,       &bounce_return_size_limit },
  { "bounce_sender_authentication",opt_stringptr,&bounce_sender_authentication },
  { "callout_domain_negative_expire", opt_time,  &callout_cache_domain_negative_expire },
  { "callout_domain_positive_expire", opt_time,  &callout_cache_domain_positive_expire },
  { "callout_negative_expire",  opt_time,        &callout_cache_negative_expire },
  { "callout_positive_expire",  opt_time,        &callout_cache_positive_expire },
  { "callout_random_local_part",opt_stringptr,   &callout_random_local_part },
  { "check_log_inodes",         opt_int,         &check_log_inodes },
  { "check_log_space",          opt_Kint,        &check_log_space },
  { "check_rfc2047_length",     opt_bool,        &check_rfc2047_length },
  { "check_spool_inodes",       opt_int,         &check_spool_inodes },
  { "check_spool_space",        opt_Kint,        &check_spool_space },
  { "chunking_advertise_hosts", opt_stringptr,	 &chunking_advertise_hosts },
  { "commandline_checks_require_admin", opt_bool,&commandline_checks_require_admin },
  { "daemon_smtp_port",         opt_stringptr|opt_hidden, &daemon_smtp_port },
  { "daemon_smtp_ports",        opt_stringptr,   &daemon_smtp_port },
  { "daemon_startup_retries",   opt_int,         &daemon_startup_retries },
  { "daemon_startup_sleep",     opt_time,        &daemon_startup_sleep },
#ifdef EXPERIMENTAL_DCC
  { "dcc_direct_add_header",    opt_bool,        &dcc_direct_add_header },
  { "dccifd_address",           opt_stringptr,   &dccifd_address },
  { "dccifd_options",           opt_stringptr,   &dccifd_options },
#endif
  { "debug_store",              opt_bool,        &debug_store },
  { "delay_warning",            opt_timelist,    &delay_warning },
  { "delay_warning_condition",  opt_stringptr,   &delay_warning_condition },
  { "deliver_drop_privilege",   opt_bool,        &deliver_drop_privilege },
  { "deliver_queue_load_max",   opt_fixed,       &deliver_queue_load_max },
  { "delivery_date_remove",     opt_bool,        &delivery_date_remove },
#ifdef ENABLE_DISABLE_FSYNC
  { "disable_fsync",            opt_bool,        &disable_fsync },
#endif
  { "disable_ipv6",             opt_bool,        &disable_ipv6 },
#ifndef DISABLE_DKIM
  { "dkim_verify_signers",      opt_stringptr,   &dkim_verify_signers },
#endif
#ifdef EXPERIMENTAL_DMARC
  { "dmarc_forensic_sender",    opt_stringptr,   &dmarc_forensic_sender },
  { "dmarc_history_file",       opt_stringptr,   &dmarc_history_file },
  { "dmarc_tld_file",           opt_stringptr,   &dmarc_tld_file },
#endif
  { "dns_again_means_nonexist", opt_stringptr,   &dns_again_means_nonexist },
  { "dns_check_names_pattern",  opt_stringptr,   &check_dns_names_pattern },
  { "dns_cname_loops",		opt_int,	 &dns_cname_loops },
  { "dns_csa_search_limit",     opt_int,         &dns_csa_search_limit },
  { "dns_csa_use_reverse",      opt_bool,        &dns_csa_use_reverse },
  { "dns_dnssec_ok",            opt_int,         &dns_dnssec_ok },
  { "dns_ipv4_lookup",          opt_stringptr,   &dns_ipv4_lookup },
  { "dns_retrans",              opt_time,        &dns_retrans },
  { "dns_retry",                opt_int,         &dns_retry },
  { "dns_trust_aa",             opt_stringptr,   &dns_trust_aa },
  { "dns_use_edns0",            opt_int,         &dns_use_edns0 },
 /* This option is now a no-op, retained for compatibility */
  { "drop_cr",                  opt_bool,        &drop_cr },
/*********************************************************/
  { "dsn_advertise_hosts",      opt_stringptr,   &dsn_advertise_hosts },
  { "dsn_from",                 opt_stringptr,   &dsn_from },
  { "envelope_to_remove",       opt_bool,        &envelope_to_remove },
  { "errors_copy",              opt_stringptr,   &errors_copy },
  { "errors_reply_to",          opt_stringptr,   &errors_reply_to },
#ifndef DISABLE_EVENT
  { "event_action",             opt_stringptr,   &event_action },
#endif
  { "exim_group",               opt_gid,         &exim_gid },
  { "exim_path",                opt_stringptr,   &exim_path },
  { "exim_user",                opt_uid,         &exim_uid },
  { "extra_local_interfaces",   opt_stringptr,   &extra_local_interfaces },
  { "extract_addresses_remove_arguments", opt_bool, &extract_addresses_remove_arguments },
  { "finduser_retries",         opt_int,         &finduser_retries },
  { "freeze_tell",              opt_stringptr,   &freeze_tell },
  { "gecos_name",               opt_stringptr,   &gecos_name },
  { "gecos_pattern",            opt_stringptr,   &gecos_pattern },
#ifdef SUPPORT_TLS
  { "gnutls_allow_auto_pkcs11", opt_bool,        &gnutls_allow_auto_pkcs11 },
  { "gnutls_compat_mode",       opt_bool,        &gnutls_compat_mode },
#endif
  { "header_line_maxsize",      opt_int,         &header_line_maxsize },
  { "header_maxsize",           opt_int,         &header_maxsize },
  { "headers_charset",          opt_stringptr,   &headers_charset },
  { "helo_accept_junk_hosts",   opt_stringptr,   &helo_accept_junk_hosts },
  { "helo_allow_chars",         opt_stringptr,   &helo_allow_chars },
  { "helo_lookup_domains",      opt_stringptr,   &helo_lookup_domains },
  { "helo_try_verify_hosts",    opt_stringptr,   &helo_try_verify_hosts },
  { "helo_verify_hosts",        opt_stringptr,   &helo_verify_hosts },
  { "hold_domains",             opt_stringptr,   &hold_domains },
  { "host_lookup",              opt_stringptr,   &host_lookup },
  { "host_lookup_order",        opt_stringptr,   &host_lookup_order },
  { "host_reject_connection",   opt_stringptr,   &host_reject_connection },
  { "hosts_connection_nolog",   opt_stringptr,   &hosts_connection_nolog },
#ifdef SUPPORT_PROXY
  { "hosts_proxy",              opt_stringptr,   &hosts_proxy },
#endif
  { "hosts_treat_as_local",     opt_stringptr,   &hosts_treat_as_local },
#ifdef LOOKUP_IBASE
  { "ibase_servers",            opt_stringptr,   &ibase_servers },
#endif
  { "ignore_bounce_errors_after", opt_time,      &ignore_bounce_errors_after },
  { "ignore_fromline_hosts",    opt_stringptr,   &ignore_fromline_hosts },
  { "ignore_fromline_local",    opt_bool,        &ignore_fromline_local },
  { "keep_environment",         opt_stringptr,   &keep_environment },
  { "keep_malformed",           opt_time,        &keep_malformed },
#ifdef LOOKUP_LDAP
  { "ldap_ca_cert_dir",         opt_stringptr,   &eldap_ca_cert_dir },
  { "ldap_ca_cert_file",        opt_stringptr,   &eldap_ca_cert_file },
  { "ldap_cert_file",           opt_stringptr,   &eldap_cert_file },
  { "ldap_cert_key",            opt_stringptr,   &eldap_cert_key },
  { "ldap_cipher_suite",        opt_stringptr,   &eldap_cipher_suite },
  { "ldap_default_servers",     opt_stringptr,   &eldap_default_servers },
  { "ldap_require_cert",        opt_stringptr,   &eldap_require_cert },
  { "ldap_start_tls",           opt_bool,        &eldap_start_tls },
  { "ldap_version",             opt_int,         &eldap_version },
#endif
  { "local_from_check",         opt_bool,        &local_from_check },
  { "local_from_prefix",        opt_stringptr,   &local_from_prefix },
  { "local_from_suffix",        opt_stringptr,   &local_from_suffix },
  { "local_interfaces",         opt_stringptr,   &local_interfaces },
#ifdef HAVE_LOCAL_SCAN
  { "local_scan_timeout",       opt_time,        &local_scan_timeout },
#endif
  { "local_sender_retain",      opt_bool,        &local_sender_retain },
  { "localhost_number",         opt_stringptr,   &host_number_string },
  { "log_file_path",            opt_stringptr,   &log_file_path },
  { "log_selector",             opt_stringptr,   &log_selector_string },
  { "log_timezone",             opt_bool,        &log_timezone },
  { "lookup_open_max",          opt_int,         &lookup_open_max },
  { "max_username_length",      opt_int,         &max_username_length },
  { "message_body_newlines",    opt_bool,        &message_body_newlines },
  { "message_body_visible",     opt_mkint,       &message_body_visible },
  { "message_id_header_domain", opt_stringptr,   &message_id_domain },
  { "message_id_header_text",   opt_stringptr,   &message_id_text },
  { "message_logs",             opt_bool,        &message_logs },
  { "message_size_limit",       opt_stringptr,   &message_size_limit },
#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
  { "move_frozen_messages",     opt_bool,        &move_frozen_messages },
#endif
  { "mua_wrapper",              opt_bool,        &mua_wrapper },
#ifdef LOOKUP_MYSQL
  { "mysql_servers",            opt_stringptr,   &mysql_servers },
#endif
  { "never_users",              opt_uidlist,     &never_users },
#ifdef SUPPORT_TLS
  { "openssl_options",          opt_stringptr,   &openssl_options },
#endif
#ifdef LOOKUP_ORACLE
  { "oracle_servers",           opt_stringptr,   &oracle_servers },
#endif
  { "percent_hack_domains",     opt_stringptr,   &percent_hack_domains },
#ifdef EXIM_PERL
  { "perl_at_start",            opt_bool,        &opt_perl_at_start },
  { "perl_startup",             opt_stringptr,   &opt_perl_startup },
  { "perl_taintmode",           opt_bool,        &opt_perl_taintmode },
#endif
#ifdef LOOKUP_PGSQL
  { "pgsql_servers",            opt_stringptr,   &pgsql_servers },
#endif
  { "pid_file_path",            opt_stringptr,   &pid_file_path },
  { "pipelining_advertise_hosts", opt_stringptr, &pipelining_advertise_hosts },
#ifdef EXPERIMENTAL_PIPE_CONNECT
  { "pipelining_connect_advertise_hosts", opt_stringptr,
						 &pipe_connect_advertise_hosts },
#endif
#ifndef DISABLE_PRDR
  { "prdr_enable",              opt_bool,        &prdr_enable },
#endif
  { "preserve_message_logs",    opt_bool,        &preserve_message_logs },
  { "primary_hostname",         opt_stringptr,   &primary_hostname },
  { "print_topbitchars",        opt_bool,        &print_topbitchars },
  { "process_log_path",         opt_stringptr,   &process_log_path },
  { "prod_requires_admin",      opt_bool,        &prod_requires_admin },
  { "qualify_domain",           opt_stringptr,   &qualify_domain_sender },
  { "qualify_recipient",        opt_stringptr,   &qualify_domain_recipient },
  { "queue_domains",            opt_stringptr,   &queue_domains },
  { "queue_list_requires_admin",opt_bool,        &queue_list_requires_admin },
  { "queue_only",               opt_bool,        &queue_only },
  { "queue_only_file",          opt_stringptr,   &queue_only_file },
  { "queue_only_load",          opt_fixed,       &queue_only_load },
  { "queue_only_load_latch",    opt_bool,        &queue_only_load_latch },
  { "queue_only_override",      opt_bool,        &queue_only_override },
  { "queue_run_in_order",       opt_bool,        &queue_run_in_order },
  { "queue_run_max",            opt_stringptr,   &queue_run_max },
  { "queue_smtp_domains",       opt_stringptr,   &queue_smtp_domains },
  { "receive_timeout",          opt_time,        &receive_timeout },
  { "received_header_text",     opt_stringptr,   &received_header_text },
  { "received_headers_max",     opt_int,         &received_headers_max },
  { "recipient_unqualified_hosts", opt_stringptr, &recipient_unqualified_hosts },
  { "recipients_max",           opt_int,         &recipients_max },
  { "recipients_max_reject",    opt_bool,        &recipients_max_reject },
#ifdef LOOKUP_REDIS
  { "redis_servers",            opt_stringptr,   &redis_servers },
#endif
  { "remote_max_parallel",      opt_int,         &remote_max_parallel },
  { "remote_sort_domains",      opt_stringptr,   &remote_sort_domains },
  { "retry_data_expire",        opt_time,        &retry_data_expire },
  { "retry_interval_max",       opt_time,        &retry_interval_max },
  { "return_path_remove",       opt_bool,        &return_path_remove },
  { "return_size_limit",        opt_mkint|opt_hidden, &bounce_return_size_limit },
  { "rfc1413_hosts",            opt_stringptr,   &rfc1413_hosts },
  { "rfc1413_query_timeout",    opt_time,        &rfc1413_query_timeout },
  { "sender_unqualified_hosts", opt_stringptr,   &sender_unqualified_hosts },
  { "slow_lookup_log",          opt_int,         &slow_lookup_log },
  { "smtp_accept_keepalive",    opt_bool,        &smtp_accept_keepalive },
  { "smtp_accept_max",          opt_int,         &smtp_accept_max },
  { "smtp_accept_max_nonmail",  opt_int,         &smtp_accept_max_nonmail },
  { "smtp_accept_max_nonmail_hosts", opt_stringptr, &smtp_accept_max_nonmail_hosts },
  { "smtp_accept_max_per_connection", opt_int,   &smtp_accept_max_per_connection },
  { "smtp_accept_max_per_host", opt_stringptr,   &smtp_accept_max_per_host },
  { "smtp_accept_queue",        opt_int,         &smtp_accept_queue },
  { "smtp_accept_queue_per_connection", opt_int, &smtp_accept_queue_per_connection },
  { "smtp_accept_reserve",      opt_int,         &smtp_accept_reserve },
  { "smtp_active_hostname",     opt_stringptr,   &raw_active_hostname },
  { "smtp_banner",              opt_stringptr,   &smtp_banner },
  { "smtp_check_spool_space",   opt_bool,        &smtp_check_spool_space },
  { "smtp_connect_backlog",     opt_int,         &smtp_connect_backlog },
  { "smtp_enforce_sync",        opt_bool,        &smtp_enforce_sync },
  { "smtp_etrn_command",        opt_stringptr,   &smtp_etrn_command },
  { "smtp_etrn_serialize",      opt_bool,        &smtp_etrn_serialize },
  { "smtp_load_reserve",        opt_fixed,       &smtp_load_reserve },
  { "smtp_max_synprot_errors",  opt_int,         &smtp_max_synprot_errors },
  { "smtp_max_unknown_commands",opt_int,         &smtp_max_unknown_commands },
  { "smtp_ratelimit_hosts",     opt_stringptr,   &smtp_ratelimit_hosts },
  { "smtp_ratelimit_mail",      opt_stringptr,   &smtp_ratelimit_mail },
  { "smtp_ratelimit_rcpt",      opt_stringptr,   &smtp_ratelimit_rcpt },
  { "smtp_receive_timeout",     opt_func,        &fn_smtp_receive_timeout },
  { "smtp_reserve_hosts",       opt_stringptr,   &smtp_reserve_hosts },
  { "smtp_return_error_details",opt_bool,        &smtp_return_error_details },
#ifdef SUPPORT_I18N
  { "smtputf8_advertise_hosts", opt_stringptr,   &smtputf8_advertise_hosts },
#endif
#ifdef WITH_CONTENT_SCAN
  { "spamd_address",            opt_stringptr,   &spamd_address },
#endif
#ifdef SUPPORT_SPF
  { "spf_guess",                opt_stringptr,   &spf_guess },
#endif
  { "split_spool_directory",    opt_bool,        &split_spool_directory },
  { "spool_directory",          opt_stringptr,   &spool_directory },
  { "spool_wireformat",         opt_bool,        &spool_wireformat },
#ifdef LOOKUP_SQLITE
  { "sqlite_lock_timeout",      opt_int,         &sqlite_lock_timeout },
#endif
#ifdef EXPERIMENTAL_SRS
  { "srs_config",               opt_stringptr,   &srs_config },
  { "srs_hashlength",           opt_int,         &srs_hashlength },
  { "srs_hashmin",              opt_int,         &srs_hashmin },
  { "srs_maxage",               opt_int,         &srs_maxage },
  { "srs_secrets",              opt_stringptr,   &srs_secrets },
  { "srs_usehash",              opt_bool,        &srs_usehash },
  { "srs_usetimestamp",         opt_bool,        &srs_usetimestamp },
#endif
  { "strict_acl_vars",          opt_bool,        &strict_acl_vars },
  { "strip_excess_angle_brackets", opt_bool,     &strip_excess_angle_brackets },
  { "strip_trailing_dot",       opt_bool,        &strip_trailing_dot },
  { "syslog_duplication",       opt_bool,        &syslog_duplication },
  { "syslog_facility",          opt_stringptr,   &syslog_facility_str },
  { "syslog_pid",               opt_bool,        &syslog_pid },
  { "syslog_processname",       opt_stringptr,   &syslog_processname },
  { "syslog_timestamp",         opt_bool,        &syslog_timestamp },
  { "system_filter",            opt_stringptr,   &system_filter },
  { "system_filter_directory_transport", opt_stringptr,&system_filter_directory_transport },
  { "system_filter_file_transport",opt_stringptr,&system_filter_file_transport },
  { "system_filter_group",      opt_gid,         &system_filter_gid },
  { "system_filter_pipe_transport",opt_stringptr,&system_filter_pipe_transport },
  { "system_filter_reply_transport",opt_stringptr,&system_filter_reply_transport },
  { "system_filter_user",       opt_uid,         &system_filter_uid },
  { "tcp_nodelay",              opt_bool,        &tcp_nodelay },
#ifdef USE_TCP_WRAPPERS
  { "tcp_wrappers_daemon_name", opt_stringptr,   &tcp_wrappers_daemon_name },
#endif
  { "timeout_frozen_after",     opt_time,        &timeout_frozen_after },
  { "timezone",                 opt_stringptr,   &timezone_string },
  { "tls_advertise_hosts",      opt_stringptr,   &tls_advertise_hosts },
#ifdef SUPPORT_TLS
# ifdef EXPERIMENTAL_REQUIRETLS
  { "tls_advertise_requiretls", opt_stringptr,   &tls_advertise_requiretls },
# endif
  { "tls_certificate",          opt_stringptr,   &tls_certificate },
  { "tls_crl",                  opt_stringptr,   &tls_crl },
  { "tls_dh_max_bits",          opt_int,         &tls_dh_max_bits },
  { "tls_dhparam",              opt_stringptr,   &tls_dhparam },
  { "tls_eccurve",              opt_stringptr,   &tls_eccurve },
# ifndef DISABLE_OCSP
  { "tls_ocsp_file",            opt_stringptr,   &tls_ocsp_file },
# endif
  { "tls_on_connect_ports",     opt_stringptr,   &tls_in.on_connect_ports },
  { "tls_privatekey",           opt_stringptr,   &tls_privatekey },
  { "tls_remember_esmtp",       opt_bool,        &tls_remember_esmtp },
  { "tls_require_ciphers",      opt_stringptr,   &tls_require_ciphers },
  { "tls_try_verify_hosts",     opt_stringptr,   &tls_try_verify_hosts },
  { "tls_verify_certificates",  opt_stringptr,   &tls_verify_certificates },
  { "tls_verify_hosts",         opt_stringptr,   &tls_verify_hosts },
#endif
  { "trusted_groups",           opt_gidlist,     &trusted_groups },
  { "trusted_users",            opt_uidlist,     &trusted_users },
  { "unknown_login",            opt_stringptr,   &unknown_login },
  { "unknown_username",         opt_stringptr,   &unknown_username },
  { "untrusted_set_sender",     opt_stringptr,   &untrusted_set_sender },
  { "uucp_from_pattern",        opt_stringptr,   &uucp_from_pattern },
  { "uucp_from_sender",         opt_stringptr,   &uucp_from_sender },
  { "warn_message_file",        opt_stringptr,   &warn_message_file },
  { "write_rejectlog",          opt_bool,        &write_rejectlog }
};

#ifndef MACRO_PREDEF
static int optionlist_config_size = nelem(optionlist_config);
#endif


#ifdef MACRO_PREDEF

static void fn_smtp_receive_timeout(const uschar * name, const uschar * str) {/*Dummy*/}

void
options_main(void)
{
options_from_list(optionlist_config, nelem(optionlist_config), US"MAIN", NULL);
}

void
options_auths(void)
{
struct auth_info * ai;
uschar buf[64];

options_from_list(optionlist_auths, optionlist_auths_size, US"AUTHENTICATORS", NULL);

for (ai = auths_available; ai->driver_name[0]; ai++)
  {
  spf(buf, sizeof(buf), US"_DRIVER_AUTHENTICATOR_%T", ai->driver_name);
  builtin_macro_create(buf);
  options_from_list(ai->options, (unsigned)*ai->options_count, US"AUTHENTICATOR", ai->driver_name);
  }
}

void
options_logging(void)
{
bit_table * bp;
uschar buf[64];

for (bp = log_options; bp < log_options + log_options_count; bp++)
  {
  spf(buf, sizeof(buf), US"_LOG_%T", bp->name);
  builtin_macro_create(buf);
  }
}


#else	/*!MACRO_PREDEF*/

extern char **environ;

static void save_config_line(const uschar* line);
static void save_config_position(const uschar *file, int line);
static void print_config(BOOL admin, BOOL terse);


#define CSTATE_STACK_SIZE 10

const uschar *config_directory = NULL;


/* Structure for chain (stack) of .included files */

typedef struct config_file_item {
  struct config_file_item *next;
  const uschar *filename;
  const uschar *directory;
  FILE *file;
  int lineno;
} config_file_item;

/* Structure for chain of configuration lines (-bP config) */

typedef struct config_line_item {
  struct config_line_item *next;
  uschar *line;
} config_line_item;

static config_line_item* config_lines;

/* Structure of table of conditional words and their state transitions */

typedef struct cond_item {
  uschar *name;
  int    namelen;
  int    action1;
  int    action2;
  int    pushpop;
} cond_item;

/* Structure of table of syslog facility names and values */

typedef struct syslog_fac_item {
  uschar *name;
  int    value;
} syslog_fac_item;

/* constants */
static const char * const hidden = "<value not displayable>";

/* Static variables */

static config_file_item *config_file_stack = NULL;  /* For includes */

static uschar *syslog_facility_str  = NULL;
static uschar next_section[24];
static uschar time_buffer[24];

/* State variables for conditional loading (.ifdef / .else / .endif) */

static int cstate = 0;
static int cstate_stack_ptr = -1;
static int cstate_stack[CSTATE_STACK_SIZE];

/* Table of state transitions for handling conditional inclusions. There are
four possible state transitions:

  .ifdef true
  .ifdef false
  .elifdef true  (or .else)
  .elifdef false

.endif just causes the previous cstate to be popped off the stack */

static int next_cstate[3][4] =
  {
  /* State 0: reading from file, or reading until next .else or .endif */
  { 0, 1, 2, 2 },
  /* State 1: condition failed, skipping until next .else or .endif */
  { 2, 2, 0, 1 },
  /* State 2: skipping until .endif */
  { 2, 2, 2, 2 },
  };

/* Table of conditionals and the states to set. For each name, there are four
values: the length of the name (to save computing it each time), the state to
set if a macro was found in the line, the state to set if a macro was not found
in the line, and a stack manipulation setting which is:

  -1   pull state value off the stack
   0   don't alter the stack
  +1   push value onto stack, before setting new state
*/

static cond_item cond_list[] = {
  { US"ifdef",    5, 0, 1,  1 },
  { US"ifndef",   6, 1, 0,  1 },
  { US"elifdef",  7, 2, 3,  0 },
  { US"elifndef", 8, 3, 2,  0 },
  { US"else",     4, 2, 2,  0 },
  { US"endif",    5, 0, 0, -1 }
};

static int cond_list_size = sizeof(cond_list)/sizeof(cond_item);

/* Table of syslog facility names and their values */

static syslog_fac_item syslog_list[] = {
  { US"mail",   LOG_MAIL },
  { US"user",   LOG_USER },
  { US"news",   LOG_NEWS },
  { US"uucp",   LOG_UUCP },
  { US"local0", LOG_LOCAL0 },
  { US"local1", LOG_LOCAL1 },
  { US"local2", LOG_LOCAL2 },
  { US"local3", LOG_LOCAL3 },
  { US"local4", LOG_LOCAL4 },
  { US"local5", LOG_LOCAL5 },
  { US"local6", LOG_LOCAL6 },
  { US"local7", LOG_LOCAL7 },
  { US"daemon", LOG_DAEMON }
};

static int syslog_list_size = sizeof(syslog_list)/sizeof(syslog_fac_item);




/*************************************************
*         Find the name of an option             *
*************************************************/

/* This function is to aid debugging. Various functions take arguments that are
pointer variables in the options table or in option tables for various drivers.
For debugging output, it is useful to be able to find the name of the option
which is currently being processed. This function finds it, if it exists, by
searching the table(s).

Arguments:   a value that is presumed to be in the table above
Returns:     the option name, or an empty string
*/

uschar *
readconf_find_option(void *p)
{
int i;
router_instance *r;
transport_instance *t;

for (i = 0; i < nelem(optionlist_config); i++)
  if (p == optionlist_config[i].value) return US optionlist_config[i].name;

for (r = routers; r; r = r->next)
  {
  router_info *ri = r->info;
  for (i = 0; i < *ri->options_count; i++)
    {
    if ((ri->options[i].type & opt_mask) != opt_stringptr) continue;
    if (p == CS (r->options_block) + (long int)(ri->options[i].value))
      return US ri->options[i].name;
    }
  }

for (t = transports; t; t = t->next)
  {
  transport_info *ti = t->info;
  for (i = 0; i < *ti->options_count; i++)
    {
    optionlist * op = &ti->options[i];
    if ((op->type & opt_mask) != opt_stringptr) continue;
    if (p == (  op->type & opt_public
	     ? CS t
	     : CS t->options_block
	     )
	     + (long int)op->value)
	return US op->name;
    }
  }

return US"";
}




/*************************************************
*       Deal with an assignment to a macro       *
*************************************************/

/* We have a new definition; append to the list.

Args:
 name	Name of the macro; will be copied
 val	Expansion result for the macro; will be copied
*/

macro_item *
macro_create(const uschar * name, const uschar * val, BOOL command_line)
{
macro_item * m = store_get(sizeof(macro_item));

READCONF_DEBUG fprintf(stderr, "%s: '%s' '%s'\n", __FUNCTION__, name, val);
m->next = NULL;
m->command_line = command_line;
m->namelen = Ustrlen(name);
m->replen = Ustrlen(val);
m->name = string_copy(name);
m->replacement = string_copy(val);
if (mlast)
  mlast->next = m;
else
  macros = m;
mlast = m;
if (!macros_user)
  macros_user = m;
return m;
}


/* This function is called when a line that starts with an upper case letter is
encountered. The argument "line" should contain a complete logical line, and
start with the first letter of the macro name. The macro name and the
replacement text are extracted and stored. Redefinition of existing,
non-command line, macros is permitted using '==' instead of '='.

Arguments:
  s            points to the start of the logical line

Returns:       FALSE iff fatal error
*/

BOOL
macro_read_assignment(uschar *s)
{
uschar name[64];
int namelen = 0;
BOOL redef = FALSE;
macro_item *m;

while (isalnum(*s) || *s == '_')
  {
  if (namelen >= sizeof(name) - 1)
    {
    log_write(0, LOG_PANIC|LOG_CONFIG_IN,
      "macro name too long (maximum is " SIZE_T_FMT " characters)", sizeof(name) - 1);
    return FALSE;
    }
  name[namelen++] = *s++;
  }
name[namelen] = 0;

while (isspace(*s)) s++;
if (*s++ != '=')
  {
  log_write(0, LOG_PANIC|LOG_CONFIG_IN, "malformed macro definition");
  return FALSE;
  }

if (*s == '=')
  {
  redef = TRUE;
  s++;
  }
while (isspace(*s)) s++;

/* If an existing macro of the same name was defined on the command line, we
just skip this definition. It's an error to attempt to redefine a macro without
redef set to TRUE, or to redefine a macro when it hasn't been defined earlier.
It is also an error to define a macro whose name begins with the name of a
previously defined macro.  This is the requirement that make using a tree
for macros hard; we must check all macros for the substring.  Perhaps a
sorted list, and a bsearch, would work?
Note: it is documented that the other way round works. */

for (m = macros; m; m = m->next)
  {
  if (Ustrcmp(m->name, name) == 0)
    {
    if (!m->command_line && !redef)
      {
      log_write(0, LOG_CONFIG|LOG_PANIC, "macro \"%s\" is already "
       "defined (use \"==\" if you want to redefine it)", name);
      return FALSE;
      }
    break;
    }

  if (m->namelen < namelen && Ustrstr(name, m->name) != NULL)
    {
    log_write(0, LOG_CONFIG|LOG_PANIC, "\"%s\" cannot be defined as "
      "a macro because previously defined macro \"%s\" is a substring",
      name, m->name);
    return FALSE;
    }

  /* We cannot have this test, because it is documented that a substring
  macro is permitted (there is even an example).
  *
  * if (m->namelen > namelen && Ustrstr(m->name, name) != NULL)
  *   log_write(0, LOG_CONFIG|LOG_PANIC_DIE, "\"%s\" cannot be defined as "
  *     "a macro because it is a substring of previously defined macro \"%s\"",
  *     name, m->name);
  */
  }

/* Check for an overriding command-line definition. */

if (m && m->command_line) return TRUE;

/* Redefinition must refer to an existing macro. */

if (redef)
  if (m)
    {
    m->replen = Ustrlen(s);
    m->replacement = string_copy(s);
    }
  else
    {
    log_write(0, LOG_CONFIG|LOG_PANIC, "can't redefine an undefined macro "
      "\"%s\"", name);
    return FALSE;
    }

/* We have a new definition. */
else
  (void) macro_create(name, s, FALSE);
return TRUE;
}





/* Process line for macros. The line is in big_buffer starting at offset len.
Expand big_buffer if needed.  Handle definitions of new macros, and
macro expansions, rewriting the line in the buffer.

Arguments:
 len		Offset in buffer of start of line
 newlen		Pointer to offset of end of line, updated on return
 macro_found	Pointer to return that a macro was expanded

Return: pointer to first nonblank char in line
*/

uschar *
macros_expand(int len, int * newlen, BOOL * macro_found)
{
uschar * ss = big_buffer + len;
uschar * s;
macro_item * m;

/* Find the true start of the physical line - leading spaces are always
ignored. */

while (isspace(*ss)) ss++;

/* Process the physical line for macros. If this is the start of the logical
line, skip over initial text at the start of the line if it starts with an
upper case character followed by a sequence of name characters and an equals
sign, because that is the definition of a new macro, and we don't do
replacement therein. */

s = ss;
if (len == 0 && isupper(*s))
  {
  while (isalnum(*s) || *s == '_') s++;
  while (isspace(*s)) s++;
  if (*s != '=') s = ss;          /* Not a macro definition */
  }

/* Skip leading chars which cannot start a macro name, to avoid multiple
pointless rescans in Ustrstr calls. */

while (*s && !isupper(*s) && !(*s == '_' && isupper(s[1]))) s++;

/* For each defined macro, scan the line (from after XXX= if present),
replacing all occurrences of the macro. */

*macro_found = FALSE;
if (*s) for (m = *s == '_' ? macros : macros_user; m; m = m->next)
  {
  uschar * p, *pp;
  uschar * t;

  while (*s && !isupper(*s) && !(*s == '_' && isupper(s[1]))) s++;
  if (!*s) break;

  t = s;
  while ((p = Ustrstr(t, m->name)) != NULL)
    {
    int moveby;

    READCONF_DEBUG fprintf(stderr, "%s: matched '%s' in '%.*s'\n", __FUNCTION__,
      m->name, (int) Ustrlen(ss)-1, ss);
    /* Expand the buffer if necessary */

    while (*newlen - m->namelen + m->replen + 1 > big_buffer_size)
      {
      int newsize = big_buffer_size + BIG_BUFFER_SIZE;
      uschar *newbuffer = store_malloc(newsize);
      memcpy(newbuffer, big_buffer, *newlen + 1);
      p = newbuffer  + (p - big_buffer);
      s = newbuffer  + (s - big_buffer);
      ss = newbuffer + (ss - big_buffer);
      t = newbuffer  + (t - big_buffer);
      big_buffer_size = newsize;
      store_free(big_buffer);
      big_buffer = newbuffer;
      }

    /* Shuffle the remaining characters up or down in the buffer before
    copying in the replacement text. Don't rescan the replacement for this
    same macro. */

    pp = p + m->namelen;
    if ((moveby = m->replen - m->namelen) != 0)
      {
      memmove(p + m->replen, pp, (big_buffer + *newlen) - pp + 1);
      *newlen += moveby;
      }
    Ustrncpy(p, m->replacement, m->replen);
    t = p + m->replen;
    while (*t && !isupper(*t) && !(*t == '_' && isupper(t[1]))) t++;
    *macro_found = TRUE;
    }
  }

/* An empty macro replacement at the start of a line could mean that ss no
longer points to the first non-blank character. */

while (isspace(*ss)) ss++;
return ss;
}

/*************************************************
*            Read configuration line             *
*************************************************/

/* A logical line of text is read from the configuration file into the big
buffer, taking account of macros, .includes, and continuations. The size of
big_buffer is increased if necessary. The count of configuration lines is
maintained. Physical input lines starting with # (ignoring leading white space,
and after macro replacement) and empty logical lines are always ignored.
Leading and trailing spaces are removed.

If we hit a line of the form "begin xxxx", the xxxx is placed in the
next_section vector, and the function returns NULL, indicating the end of a
configuration section. On end-of-file, NULL is returned with next_section
empty.

Arguments:      none

Returns:        a pointer to the first non-blank in the line,
                or NULL if eof or end of section is reached
*/

static uschar *
get_config_line(void)
{
int startoffset = 0;         /* To first non-blank char in logical line */
int len = 0;                 /* Of logical line so far */
int newlen;
uschar *s, *ss;
BOOL macro_found;

/* Loop for handling continuation lines, skipping comments, and dealing with
.include files. */

for (;;)
  {
  if (Ufgets(big_buffer+len, big_buffer_size-len, config_file) == NULL)
    {
    if (config_file_stack != NULL)    /* EOF inside .include */
      {
      (void)fclose(config_file);
      config_file = config_file_stack->file;
      config_filename = config_file_stack->filename;
      config_directory = config_file_stack->directory;
      config_lineno = config_file_stack->lineno;
      config_file_stack = config_file_stack->next;
      if (config_lines)
        save_config_position(config_filename, config_lineno);
      continue;
      }

    /* EOF at top level */

    if (cstate_stack_ptr >= 0)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
        "Unexpected end of configuration file: .endif missing");

    if (len != 0) break;        /* EOF after continuation */
    next_section[0] = 0;        /* EOF at start of logical line */
    return NULL;
    }

  config_lineno++;
  newlen = len + Ustrlen(big_buffer + len);

  if (config_lines && config_lineno == 1)
    save_config_position(config_filename, config_lineno);

  /* Handle pathologically long physical lines - yes, it did happen - by
  extending big_buffer at this point. The code also copes with very long
  logical lines. */

  while (newlen == big_buffer_size - 1 && big_buffer[newlen - 1] != '\n')
    {
    uschar *newbuffer;
    big_buffer_size += BIG_BUFFER_SIZE;
    newbuffer = store_malloc(big_buffer_size);

    /* This use of strcpy is OK because we know that the string in the old
    buffer is shorter than the new buffer. */

    Ustrcpy(newbuffer, big_buffer);
    store_free(big_buffer);
    big_buffer = newbuffer;
    if (Ufgets(big_buffer+newlen, big_buffer_size-newlen, config_file) == NULL)
      break;
    newlen += Ustrlen(big_buffer + newlen);
    }

  ss = macros_expand(len, &newlen, &macro_found);

  /* Check for comment lines - these are physical lines. */

  if (*ss == '#') continue;

  /* Handle conditionals, which are also applied to physical lines. Conditions
  are of the form ".ifdef ANYTEXT" and are treated as true if any macro
  expansion occurred on the rest of the line. A preliminary test for the leading
  '.' saves effort on most lines. */

  if (*ss == '.')
    {
    int i;

    /* Search the list of conditional directives */

    for (i = 0; i < cond_list_size; i++)
      {
      int n;
      cond_item *c = cond_list+i;
      if (Ustrncmp(ss+1, c->name, c->namelen) != 0) continue;

      /* The following character must be white space or end of string */

      n = ss[1 + c->namelen];
      if (n != ' ' && n != 't' && n != '\n' && n != 0) break;

      /* .ifdef and .ifndef push the current state onto the stack, then set
      a new one from the table. Stack overflow is an error */

      if (c->pushpop > 0)
        {
        if (cstate_stack_ptr >= CSTATE_STACK_SIZE - 1)
          log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
            ".%s nested too deeply", c->name);
        cstate_stack[++cstate_stack_ptr] = cstate;
        cstate = next_cstate[cstate][macro_found? c->action1 : c->action2];
        }

      /* For any of the others, stack underflow is an error. The next state
      comes either from the stack (.endif) or from the table. */

      else
        {
        if (cstate_stack_ptr < 0)
          log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
            ".%s without matching .ifdef", c->name);
        cstate = (c->pushpop < 0)? cstate_stack[cstate_stack_ptr--] :
          next_cstate[cstate][macro_found? c->action1 : c->action2];
        }

      /* Having dealt with a directive, break the loop */

      break;
      }

    /* If we have handled a conditional directive, continue with the next
    physical line. Otherwise, fall through. */

    if (i < cond_list_size) continue;
    }

  /* If the conditional state is not 0 (actively using these lines), ignore
  this input line. */

  if (cstate != 0) continue;  /* Conditional skip */

  /* Handle .include lines - these are also physical lines. */

  if (Ustrncmp(ss, ".include", 8) == 0 &&
       (isspace(ss[8]) ||
         (Ustrncmp(ss+8, "_if_exists", 10) == 0 && isspace(ss[18]))))
    {
    uschar *t;
    int include_if_exists = isspace(ss[8])? 0 : 10;
    config_file_item *save;
    struct stat statbuf;

    ss += 9 + include_if_exists;
    while (isspace(*ss)) ss++;
    t = ss + Ustrlen(ss);
    while (t > ss && isspace(t[-1])) t--;
    if (*ss == '\"' && t[-1] == '\"')
      {
      ss++;
      t--;
      }
    *t = 0;

    /* We allow relative file names. For security reasons currently
    relative names not allowed with .include_if_exists. For .include_if_exists
    we need to check the permissions/ownership of the containing folder */
    if (*ss != '/')
      if (include_if_exists) log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, ".include specifies a non-"
          "absolute path \"%s\"", ss);
      else
        {
	gstring * g = string_append(NULL, 3, config_directory, "/", ss);
	ss = string_from_gstring(g);
        }

    if (include_if_exists != 0 && (Ustat(ss, &statbuf) != 0)) continue;

    if (config_lines)
      save_config_position(config_filename, config_lineno);
    save = store_get(sizeof(config_file_item));
    save->next = config_file_stack;
    config_file_stack = save;
    save->file = config_file;
    save->filename = config_filename;
    save->directory = config_directory;
    save->lineno = config_lineno;

    if (!(config_file = Ufopen(ss, "rb")))
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "failed to open included "
        "configuration file %s", ss);

    config_filename = string_copy(ss);
    config_directory = string_copyn(ss, CUstrrchr(ss, '/') - ss);
    config_lineno = 0;
    continue;
    }

  /* If this is the start of the logical line, remember where the non-blank
  data starts. Otherwise shuffle down continuation lines to remove leading
  white space. */

  if (len == 0)
    startoffset = ss - big_buffer;
  else
    {
    s = big_buffer + len;
    if (ss > s)
      {
      memmove(s, ss, (newlen - len) -  (ss - s) + 1);
      newlen -= ss - s;
      }
    }

  /* Accept the new addition to the line. Remove trailing white space. */

  len = newlen;
  while (len > 0 && isspace(big_buffer[len-1])) len--;
  big_buffer[len] = 0;

  /* We are done if the line does not end in backslash and contains some data.
  Empty logical lines are ignored. For continuations, remove the backslash and
  go round the loop to read the continuation line. */

  if (len > 0)
    {
    if (big_buffer[len-1] != '\\') break;   /* End of logical line */
    big_buffer[--len] = 0;                  /* Remove backslash */
    }
  }     /* Loop for reading multiple physical lines */

/* We now have a logical line. Test for the end of a configuration section (or,
more accurately, for the start of the next section). Place the name of the next
section in next_section, and return NULL. If the name given is longer than
next_section, truncate it. It will be unrecognized later, because all the known
section names do fit. Leave space for pluralizing. */

s = big_buffer + startoffset;            /* First non-space character */

if (config_lines)
  save_config_line(s);

if (strncmpic(s, US"begin ", 6) == 0)
  {
  s += 6;
  while (isspace(*s)) s++;
  if (big_buffer + len - s > sizeof(next_section) - 2)
    s[sizeof(next_section) - 2] = 0;
  Ustrcpy(next_section, s);
  return NULL;
  }

/* Return the first non-blank character. */

return s;
}



/*************************************************
*             Read a name                        *
*************************************************/

/* The yield is the pointer to the next uschar. Names longer than the
output space are silently truncated. This function is also used from acl.c when
parsing ACLs.

Arguments:
  name      where to put the name
  len       length of name
  s         input pointer

Returns:    new input pointer
*/

uschar *
readconf_readname(uschar *name, int len, uschar *s)
{
int p = 0;
while (isspace(*s)) s++;
if (isalpha(*s))
  {
  while (isalnum(*s) || *s == '_')
    {
    if (p < len-1) name[p++] = *s;
    s++;
    }
  }
name[p] = 0;
while (isspace(*s)) s++;
return s;
}




/*************************************************
*          Read a time value                     *
*************************************************/

/* This function is also called from outside, to read argument
time values. The format of a time value is:

  [<n>w][<n>d][<n>h][<n>m][<n>s]

as long as at least one is present. If a format error is encountered,
return a negative value. The value must be terminated by the given
terminator.

Arguments:
  s             input pointer
  terminator    required terminating character
  return_msec   if TRUE, allow fractional seconds and return milliseconds

Returns:        the time value, or -1 on syntax error
                value is seconds if return_msec is FALSE
                value is milliseconds if return_msec is TRUE
*/

int
readconf_readtime(const uschar *s, int terminator, BOOL return_msec)
{
int yield = 0;
for (;;)
  {
  int value, count;
  double fraction;

  if (!isdigit(*s)) return -1;
  (void)sscanf(CCS s, "%d%n", &value, &count);
  s += count;

  switch (*s)
    {
    case 'w': value *= 7;
    case 'd': value *= 24;
    case 'h': value *= 60;
    case 'm': value *= 60;
    case 's': s++;
    break;

    case '.':
    if (!return_msec) return -1;
    (void)sscanf(CCS s, "%lf%n", &fraction, &count);
    s += count;
    if (*s++ != 's') return -1;
    yield += (int)(fraction * 1000.0);
    break;

    default: return -1;
    }

  if (return_msec) value *= 1000;
  yield += value;
  if (*s == terminator) return yield;
  }
/* Control never reaches here. */
}



/*************************************************
*          Read a fixed point value              *
*************************************************/

/* The value is returned *1000

Arguments:
  s           input pointer
  terminator  required terminator

Returns:      the value, or -1 on error
*/

static int
readconf_readfixed(const uschar *s, int terminator)
{
int yield = 0;
int value, count;
if (!isdigit(*s)) return -1;
(void)sscanf(CS  s, "%d%n", &value, &count);
s += count;
yield = value * 1000;
if (*s == '.')
  {
  int m = 100;
  while (isdigit((*(++s))))
    {
    yield += (*s - '0') * m;
    m /= 10;
    }
  }

return (*s == terminator)? yield : (-1);
}



/*************************************************
*            Find option in list                 *
*************************************************/

/* The lists are always in order, so binary chop can be used.

Arguments:
  name      the option name to search for
  ol        the first entry in the option list
  last      one more than the offset of the last entry in the option list

Returns:    pointer to an option entry, or NULL if not found
*/

static optionlist *
find_option(uschar *name, optionlist *ol, int last)
{
int first = 0;
while (last > first)
  {
  int middle = (first + last)/2;
  int c = Ustrcmp(name, ol[middle].name);

  if (c == 0) return ol + middle;
  else if (c > 0) first = middle + 1;
  else last = middle;
  }
return NULL;
}



/*************************************************
*      Find a set flag in option list            *
*************************************************/

/* Because some versions of Unix make no restrictions on the values of uids and
gids (even negative ones), we cannot represent "unset" by a special value.
There is therefore a separate boolean variable for each one indicating whether
a value is set or not. This function returns a pointer to the boolean, given
the original option name. It is a major disaster if the flag cannot be found.

Arguments:
  name          the name of the uid or gid option
  oltop         points to the start of the relevant option list
  last          one more than the offset of the last item in the option list
  data_block    NULL when reading main options => data values in the option
                  list are absolute addresses; otherwise they are byte offsets
                  in data_block (used for driver options)

Returns:        a pointer to the boolean flag.
*/

static BOOL *
get_set_flag(uschar *name, optionlist *oltop, int last, void *data_block)
{
optionlist *ol;
uschar name2[64];
sprintf(CS name2, "*set_%.50s", name);
ol = find_option(name2, oltop, last);
if (ol == NULL) log_write(0, LOG_MAIN|LOG_PANIC_DIE,
  "Exim internal error: missing set flag for %s", name);
return (data_block == NULL)? (BOOL *)(ol->value) :
  (BOOL *)(US data_block + (long int)(ol->value));
}




/*************************************************
*    Output extra characters message and die     *
*************************************************/

/* Called when an option line has junk on the end. Sometimes this is because
the sysadmin thinks comments are permitted.

Arguments:
  s          points to the extra characters
  t1..t3     strings to insert in the log message

Returns:     doesn't return; dies
*/

static void
extra_chars_error(const uschar *s, const uschar *t1, const uschar *t2, const uschar *t3)
{
uschar *comment = US"";
if (*s == '#') comment = US" (# is comment only at line start)";
log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
  "extra characters follow %s%s%s%s", t1, t2, t3, comment);
}



/*************************************************
*              Read rewrite information          *
*************************************************/

/* Each line of rewrite information contains:

.  A complete address in the form user@domain, possibly with
   leading * for each part; or alternatively, a regex.

.  A replacement string (which will be expanded).

.  An optional sequence of one-letter flags, indicating which
   headers etc. to apply this rule to.

All this is decoded and placed into a control block. The OR of the flags is
maintained in a common word.

Arguments:
  p           points to the string that makes up the rule
  existflags  points to the overall flag word
  isglobal    TRUE if reading global rewrite rules

Returns:      the control block for the parsed rule.
*/

static rewrite_rule *
readconf_one_rewrite(const uschar *p, int *existflags, BOOL isglobal)
{
rewrite_rule *next = store_get(sizeof(rewrite_rule));

next->next = NULL;
next->key = string_dequote(&p);

while (isspace(*p)) p++;
if (*p == 0)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "missing rewrite replacement string");

next->flags = 0;
next->replacement = string_dequote(&p);

while (*p != 0) switch (*p++)
  {
  case ' ': case '\t': break;

  case 'q': next->flags |= rewrite_quit; break;
  case 'w': next->flags |= rewrite_whole; break;

  case 'h': next->flags |= rewrite_all_headers; break;
  case 's': next->flags |= rewrite_sender; break;
  case 'f': next->flags |= rewrite_from; break;
  case 't': next->flags |= rewrite_to;   break;
  case 'c': next->flags |= rewrite_cc;   break;
  case 'b': next->flags |= rewrite_bcc;  break;
  case 'r': next->flags |= rewrite_replyto; break;

  case 'E': next->flags |= rewrite_all_envelope; break;
  case 'F': next->flags |= rewrite_envfrom; break;
  case 'T': next->flags |= rewrite_envto; break;

  case 'Q': next->flags |= rewrite_qualify; break;
  case 'R': next->flags |= rewrite_repeat; break;

  case 'S':
  next->flags |= rewrite_smtp;
  if (next->key[0] != '^' && Ustrncmp(next->key, "\\N^", 3) != 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "rewrite rule has the S flag but is not a regular expression");
  break;

  default:
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "unknown rewrite flag character '%c' "
    "(could be missing quotes round replacement item)", p[-1]);
  break;
  }

/* If no action flags are set, set all the "normal" rewrites. */

if ((next->flags & (rewrite_all | rewrite_smtp)) == 0)
  next->flags |= isglobal? rewrite_all : rewrite_all_headers;

/* Remember which exist, for optimization, and return the rule */

*existflags |= next->flags;
return next;
}




/*************************************************
*          Read global rewrite information       *
*************************************************/

/* Each line is a single rewrite rule; it is parsed into a control block
by readconf_one_rewrite(), and its flags are ORed into the global flag
word rewrite_existflags. */

void
readconf_rewrites(void)
{
rewrite_rule **chain = &global_rewrite_rules;
uschar *p;

while ((p = get_config_line()) != NULL)
  {
  rewrite_rule *next = readconf_one_rewrite(p, &rewrite_existflags, TRUE);
  *chain = next;
  chain = &(next->next);
  }
}



/*************************************************
*               Read a string                    *
*************************************************/

/* Strings are read into the normal store pool. As long we aren't too
near the end of the current block, the string will just use what is necessary
on the top of the stacking pool, because string_cat() uses the extension
mechanism.

Argument:
  s         the rest of the input line
  name      the option name (for errors)

Returns:    pointer to the string
*/

static uschar *
read_string(const uschar *s, const uschar *name)
{
uschar *yield;
const uschar *ss;

if (*s != '\"') return string_copy(s);

ss = s;
yield = string_dequote(&s);

if (s == ss+1 || s[-1] != '\"')
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "missing quote at end of string value for %s", name);

if (*s != 0) extra_chars_error(s, US"string value for ", name, US"");

return yield;
}


/*************************************************
*            Custom-handler options              *
*************************************************/
static void
fn_smtp_receive_timeout(const uschar * name, const uschar * str)
{
if (*str == '$')
  smtp_receive_timeout_s = string_copy(str);
else
  {
  /* "smtp_receive_timeout",     opt_time,        &smtp_receive_timeout */
  smtp_receive_timeout = readconf_readtime(str, 0, FALSE);
  if (smtp_receive_timeout < 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "invalid time value for %s",
      name);
  }
}

/*************************************************
*            Handle option line                  *
*************************************************/

/* This function is called from several places to process a line containing the
setting of an option. The first argument is the line to be decoded; it has been
checked not to be empty and not to start with '#'. Trailing newlines and white
space have been removed. The second argument is a pointer to the list of
variable names that are to be recognized, together with their types and
locations, and the third argument gives the number of entries in the list.

The fourth argument is a pointer to a data block. If it is NULL, then the data
values in the options list are absolute addresses. Otherwise, they are byte
offsets in the data block.

String option data may continue onto several lines; this function reads further
data from config_file if necessary.

The yield of this function is normally zero. If a string continues onto
multiple lines, then the data value is permitted to be followed by a comma
or a semicolon (for use in drivers) and the yield is that character.

Arguments:
  buffer        contains the configuration line to be handled
  oltop         points to the start of the relevant option list
  last          one more than the offset of the last item in the option list
  data_block    NULL when reading main options => data values in the option
                  list are absolute addresses; otherwise they are byte offsets
                  in data_block when they have opt_public set; otherwise
                  they are byte offsets in data_block->options_block.
  unknown_txt   format string to use in panic message for unknown option;
                  must contain %s for option name
                if given as NULL, don't panic on unknown option

Returns:        TRUE if an option was read successfully,
                FALSE false for an unknown option if unknown_txt == NULL,
                  otherwise panic and die on an unknown option
*/

static BOOL
readconf_handle_option(uschar *buffer, optionlist *oltop, int last,
  void *data_block, uschar *unknown_txt)
{
int ptr = 0;
int offset = 0;
int n, count, type, value;
int issecure = 0;
uid_t uid;
gid_t gid;
BOOL boolvalue = TRUE;
BOOL freesptr = TRUE;
optionlist *ol, *ol2;
struct passwd *pw;
void *reset_point;
int intbase = 0;
uschar *inttype = US"";
uschar *sptr;
uschar *s = buffer;
uschar **str_target;
uschar name[64];
uschar name2[64];

/* There may be leading spaces; thereafter, we expect an option name starting
with a letter. */

while (isspace(*s)) s++;
if (!isalpha(*s))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "option setting expected: %s", s);

/* Read the name of the option, and skip any subsequent white space. If
it turns out that what we read was "hide", set the flag indicating that
this is a secure option, and loop to read the next word. */

for (n = 0; n < 2; n++)
  {
  while (isalnum(*s) || *s == '_')
    {
    if (ptr < sizeof(name)-1) name[ptr++] = *s;
    s++;
    }
  name[ptr] = 0;
  while (isspace(*s)) s++;
  if (Ustrcmp(name, "hide") != 0) break;
  issecure = opt_secure;
  ptr = 0;
  }

/* Deal with "no_" or "not_" here for booleans */

if (Ustrncmp(name, "no_", 3) == 0)
  {
  boolvalue = FALSE;
  offset = 3;
  }

if (Ustrncmp(name, "not_", 4) == 0)
  {
  boolvalue = FALSE;
  offset = 4;
  }

/* Search the list for the given name. A non-existent name, or an option that
is set twice, is a disaster. */

if (!(ol = find_option(name + offset, oltop, last)))
  {
  if (unknown_txt == NULL) return FALSE;
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, CS unknown_txt, name);
  }

if ((ol->type & opt_set)  && !(ol->type & (opt_rep_con | opt_rep_str)))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "\"%s\" option set for the second time", name);

ol->type |= opt_set | issecure;
type = ol->type & opt_mask;

/* Types with data values must be followed by '='; the "no[t]_" prefix
applies only to boolean values. */

if (type < opt_bool || type > opt_bool_last)
  {
  if (offset != 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "negation prefix applied to a non-boolean option");
  if (*s == 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "unexpected end of line (data missing) after %s", name);
  if (*s != '=')
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "missing \"=\" after %s", name);
  }

/* If a boolean wasn't preceded by "no[t]_" it can be followed by = and
true/false/yes/no, or, in the case of opt_expand_bool, a general string that
ultimately expands to one of those values. */

else if (*s != 0 && (offset != 0 || *s != '='))
  extra_chars_error(s, US"boolean option ", name, US"");

/* Skip white space after = */

if (*s == '=') while (isspace((*(++s))));

/* If there is a data block and the opt_public flag is not set, change
the data block pointer to the private options block. */

if (data_block != NULL && (ol->type & opt_public) == 0)
  data_block = (void *)(((driver_instance *)data_block)->options_block);

/* Now get the data according to the type. */

switch (type)
  {
  /* If a string value is not enclosed in quotes, it consists of
  the rest of the current line, verbatim. Otherwise, string escapes
  are processed.

  A transport is specified as a string, which is then looked up in the
  list of transports. A search type is specified as one of a number of
  known strings.

  A set or rewrite rules for a driver is specified as a string, which is
  then parsed into a suitable chain of control blocks.

  Uids and gids are specified as strings which are then looked up in the
  passwd file. Lists of uids and gids are similarly specified as colon-
  separated strings. */

  case opt_stringptr:
  case opt_uid:
  case opt_gid:
  case opt_expand_uid:
  case opt_expand_gid:
  case opt_uidlist:
  case opt_gidlist:
  case opt_rewrite:

  reset_point = sptr = read_string(s, name);

  /* Having read a string, we now have several different ways of using it,
  depending on the data type, so do another switch. If keeping the actual
  string is not required (because it is interpreted), freesptr is set TRUE,
  and at the end we reset the pool. */

  switch (type)
    {
    /* If this was a string, set the variable to point to the new string,
    and set the flag so its store isn't reclaimed. If it was a list of rewrite
    rules, we still keep the string (for printing), and parse the rules into a
    control block and flags word. */

    case opt_stringptr:
    str_target = data_block ? USS (US data_block + (long int)(ol->value))
			    : USS (ol->value);
    if (ol->type & opt_rep_con)
      {
      uschar * saved_condition;
      /* We already have a condition, we're conducting a crude hack to let
      multiple condition rules be chained together, despite storing them in
      text form. */
      *str_target = string_copy_malloc( (saved_condition = *str_target)
	? string_sprintf("${if and{{bool_lax{%s}}{bool_lax{%s}}}}",
	    saved_condition, sptr)
	: sptr);
      /* TODO(pdp): there is a memory leak here and just below
      when we set 3 or more conditions; I still don't
      understand the store mechanism enough to know
      what's the safe way to free content from an earlier store.
      AFAICT, stores stack, so freeing an early stored item also stores
      all data alloc'd after it.  If we knew conditions were adjacent,
      we could survive that, but we don't.  So I *think* we need to take
      another bit from opt_type to indicate "malloced"; this seems like
      quite a hack, especially for this one case.  It also means that
      we can't ever reclaim the store from the *first* condition.

      Because we only do this once, near process start-up, I'm prepared to
      let this slide for the time being, even though it rankles.  */
      }
    else if (ol->type & opt_rep_str)
      {
      uschar sep_o = Ustrncmp(name, "headers_add", 11)==0 ? '\n' : ':';
      int    sep_i = -(int)sep_o;
      const uschar * list = sptr;
      uschar * s;
      gstring * list_o = NULL;

      if (*str_target)
	{
	list_o = string_get(Ustrlen(*str_target) + Ustrlen(sptr));
	list_o = string_cat(list_o, *str_target);
	}

      while ((s = string_nextinlist(&list, &sep_i, NULL, 0)))
	list_o = string_append_listele(list_o, sep_o, s);

      if (list_o)
	*str_target = string_copy_malloc(string_from_gstring(list_o));
      }
    else
      {
      *str_target = sptr;
      freesptr = FALSE;
      }
    break;

    case opt_rewrite:
    if (data_block)
      *USS (US data_block + (long int)(ol->value)) = sptr;
    else
      *USS (ol->value) = sptr;
    freesptr = FALSE;
    if (type == opt_rewrite)
      {
      int sep = 0;
      int *flagptr;
      uschar *p = sptr;
      rewrite_rule **chain;
      optionlist *ol3;

      sprintf(CS name2, "*%.50s_rules", name);
      ol2 = find_option(name2, oltop, last);
      sprintf(CS name2, "*%.50s_flags", name);
      ol3 = find_option(name2, oltop, last);

      if (ol2 == NULL || ol3 == NULL)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
          "rewrite rules not available for driver");

      if (data_block == NULL)
        {
        chain = (rewrite_rule **)(ol2->value);
        flagptr = (int *)(ol3->value);
        }
      else
        {
        chain = (rewrite_rule **)(US data_block + (long int)(ol2->value));
        flagptr = (int *)(US data_block + (long int)(ol3->value));
        }

      while ((p = string_nextinlist(CUSS &sptr, &sep, big_buffer, BIG_BUFFER_SIZE)))
        {
        rewrite_rule *next = readconf_one_rewrite(p, flagptr, FALSE);
        *chain = next;
        chain = &(next->next);
        }

      if ((*flagptr & (rewrite_all_envelope | rewrite_smtp)) != 0)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "rewrite rule specifies a "
          "non-header rewrite - not allowed at transport time -");
      }
    break;

    /* If it was an expanded uid, see if there is any expansion to be
    done by checking for the presence of a $ character. If there is, save it
    in the corresponding *expand_user option field. Otherwise, fall through
    to treat it as a fixed uid. Ensure mutual exclusivity of the two kinds
    of data. */

    case opt_expand_uid:
    sprintf(CS name2, "*expand_%.50s", name);
    ol2 = find_option(name2, oltop, last);
    if (ol2 != NULL)
      {
      uschar *ss = (Ustrchr(sptr, '$') != NULL)? sptr : NULL;

      if (data_block == NULL)
        *((uschar **)(ol2->value)) = ss;
      else
        *((uschar **)(US data_block + (long int)(ol2->value))) = ss;

      if (ss != NULL)
        {
        *(get_set_flag(name, oltop, last, data_block)) = FALSE;
        freesptr = FALSE;
        break;
        }
      }

    /* Look up a fixed uid, and also make use of the corresponding gid
    if a passwd entry is returned and the gid has not been set. */

    case opt_uid:
    if (!route_finduser(sptr, &pw, &uid))
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "user %s was not found", sptr);
    if (data_block == NULL)
      *((uid_t *)(ol->value)) = uid;
    else
      *((uid_t *)(US data_block + (long int)(ol->value))) = uid;

    /* Set the flag indicating a fixed value is set */

    *(get_set_flag(name, oltop, last, data_block)) = TRUE;

    /* Handle matching gid if we have a passwd entry: done by finding the
    same name with terminating "user" changed to "group"; if not found,
    ignore. Also ignore if the value is already set. */

    if (pw == NULL) break;
    Ustrcpy(name+Ustrlen(name)-4, "group");
    ol2 = find_option(name, oltop, last);
    if (ol2 != NULL && ((ol2->type & opt_mask) == opt_gid ||
        (ol2->type & opt_mask) == opt_expand_gid))
      {
      BOOL *set_flag = get_set_flag(name, oltop, last, data_block);
      if (! *set_flag)
        {
        if (data_block == NULL)
          *((gid_t *)(ol2->value)) = pw->pw_gid;
        else
          *((gid_t *)(US data_block + (long int)(ol2->value))) = pw->pw_gid;
        *set_flag = TRUE;
        }
      }
    break;

    /* If it was an expanded gid, see if there is any expansion to be
    done by checking for the presence of a $ character. If there is, save it
    in the corresponding *expand_user option field. Otherwise, fall through
    to treat it as a fixed gid. Ensure mutual exclusivity of the two kinds
    of data. */

    case opt_expand_gid:
    sprintf(CS name2, "*expand_%.50s", name);
    ol2 = find_option(name2, oltop, last);
    if (ol2 != NULL)
      {
      uschar *ss = (Ustrchr(sptr, '$') != NULL)? sptr : NULL;

      if (data_block == NULL)
        *((uschar **)(ol2->value)) = ss;
      else
        *((uschar **)(US data_block + (long int)(ol2->value))) = ss;

      if (ss != NULL)
        {
        *(get_set_flag(name, oltop, last, data_block)) = FALSE;
        freesptr = FALSE;
        break;
        }
      }

    /* Handle freestanding gid */

    case opt_gid:
    if (!route_findgroup(sptr, &gid))
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "group %s was not found", sptr);
    if (data_block == NULL)
      *((gid_t *)(ol->value)) = gid;
    else
      *((gid_t *)(US data_block + (long int)(ol->value))) = gid;
    *(get_set_flag(name, oltop, last, data_block)) = TRUE;
    break;

    /* If it was a uid list, look up each individual entry, and build
    a vector of uids, with a count in the first element. Put the vector
    in malloc store so we can free the string. (We are reading into
    permanent store already.) */

    case opt_uidlist:
      {
      int count = 1;
      uid_t *list;
      int ptr = 0;
      const uschar *p;
      const uschar *op = expand_string (sptr);

      if (op == NULL)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "failed to expand %s: %s",
          name, expand_string_message);

      p = op;
      if (*p != 0) count++;
      while (*p != 0) if (*p++ == ':' && *p != 0) count++;
      list = store_malloc(count*sizeof(uid_t));
      list[ptr++] = (uid_t)(count - 1);

      if (data_block == NULL)
        *((uid_t **)(ol->value)) = list;
      else
        *((uid_t **)(US data_block + (long int)(ol->value))) = list;

      p = op;
      while (count-- > 1)
        {
        int sep = 0;
        (void)string_nextinlist(&p, &sep, big_buffer, BIG_BUFFER_SIZE);
        if (!route_finduser(big_buffer, NULL, &uid))
          log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "user %s was not found",
            big_buffer);
        list[ptr++] = uid;
        }
      }
    break;

    /* If it was a gid list, look up each individual entry, and build
    a vector of gids, with a count in the first element. Put the vector
    in malloc store so we can free the string. (We are reading into permanent
    store already.) */

    case opt_gidlist:
      {
      int count = 1;
      gid_t *list;
      int ptr = 0;
      const uschar *p;
      const uschar *op = expand_string (sptr);

      if (op == NULL)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "failed to expand %s: %s",
          name, expand_string_message);

      p = op;
      if (*p != 0) count++;
      while (*p != 0) if (*p++ == ':' && *p != 0) count++;
      list = store_malloc(count*sizeof(gid_t));
      list[ptr++] = (gid_t)(count - 1);

      if (data_block == NULL)
        *((gid_t **)(ol->value)) = list;
      else
        *((gid_t **)(US data_block + (long int)(ol->value))) = list;

      p = op;
      while (count-- > 1)
        {
        int sep = 0;
        (void)string_nextinlist(&p, &sep, big_buffer, BIG_BUFFER_SIZE);
        if (!route_findgroup(big_buffer, &gid))
          log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "group %s was not found",
            big_buffer);
        list[ptr++] = gid;
        }
      }
    break;
    }

  /* Release store if the value of the string doesn't need to be kept. */

  if (freesptr) store_reset(reset_point);
  break;

  /* Expanded boolean: if no characters follow, or if there are no dollar
  characters, this is a fixed-valued boolean, and we fall through. Otherwise,
  save the string for later expansion in the alternate place. */

  case opt_expand_bool:
  if (*s != 0 && Ustrchr(s, '$') != 0)
    {
    sprintf(CS name2, "*expand_%.50s", name);
    ol2 = find_option(name2, oltop, last);
    if (ol2 != NULL)
      {
      reset_point = sptr = read_string(s, name);
      if (data_block == NULL)
        *((uschar **)(ol2->value)) = sptr;
      else
        *((uschar **)(US data_block + (long int)(ol2->value))) = sptr;
      freesptr = FALSE;
      break;
      }
    }
  /* Fall through */

  /* Boolean: if no characters follow, the value is boolvalue. Otherwise
  look for yes/not/true/false. Some booleans are stored in a single bit in
  a single int. There's a special fudge for verify settings; without a suffix
  they set both xx_sender and xx_recipient. The table points to the sender
  value; search subsequently for the recipient. There's another special case:
  opt_bool_set also notes when a boolean has been set. */

  case opt_bool:
  case opt_bit:
  case opt_bool_verify:
  case opt_bool_set:
  if (*s != 0)
    {
    s = readconf_readname(name2, 64, s);
    if (strcmpic(name2, US"true") == 0 || strcmpic(name2, US"yes") == 0)
      boolvalue = TRUE;
    else if (strcmpic(name2, US"false") == 0 || strcmpic(name2, US"no") == 0)
      boolvalue = FALSE;
    else log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "\"%s\" is not a valid value for the \"%s\" option", name2, name);
    if (*s != 0) extra_chars_error(s, string_sprintf("\"%s\" ", name2),
      US"for boolean option ", name);
    }

  /* Handle single-bit type. */

  if (type == opt_bit)
    {
    int bit = 1 << ((ol->type >> 16) & 31);
    int *ptr = (data_block == NULL)?
      (int *)(ol->value) :
      (int *)(US data_block + (long int)ol->value);
    if (boolvalue) *ptr |= bit; else *ptr &= ~bit;
    break;
    }

  /* Handle full BOOL types */

  if (data_block == NULL)
    *((BOOL *)(ol->value)) = boolvalue;
  else
    *((BOOL *)(US data_block + (long int)(ol->value))) = boolvalue;

  /* Verify fudge */

  if (type == opt_bool_verify)
    {
    sprintf(CS name2, "%.50s_recipient", name + offset);
    ol2 = find_option(name2, oltop, last);
    if (ol2 != NULL)
      {
      if (data_block == NULL)
        *((BOOL *)(ol2->value)) = boolvalue;
      else
        *((BOOL *)(US data_block + (long int)(ol2->value))) = boolvalue;
      }
    }

  /* Note that opt_bool_set type is set, if there is somewhere to do so */

  else if (type == opt_bool_set)
    {
    sprintf(CS name2, "*set_%.50s", name + offset);
    ol2 = find_option(name2, oltop, last);
    if (ol2 != NULL)
      {
      if (data_block == NULL)
        *((BOOL *)(ol2->value)) = TRUE;
      else
        *((BOOL *)(US data_block + (long int)(ol2->value))) = TRUE;
      }
    }
  break;

  /* Octal integer */

  case opt_octint:
  intbase = 8;
  inttype = US"octal ";

  /*  Integer: a simple(ish) case; allow octal and hex formats, and
  suffixes K, M, G, and T.  The different types affect output, not input. */

  case opt_mkint:
  case opt_int:
    {
    uschar *endptr;
    long int lvalue;

    errno = 0;
    lvalue = strtol(CS s, CSS &endptr, intbase);

    if (endptr == s)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "%sinteger expected for %s",
        inttype, name);

    if (errno != ERANGE && *endptr)
      {
      uschar * mp = US"TtGgMmKk\0";	/* YyZzEePpTtGgMmKk */

      if ((mp = Ustrchr(mp, *endptr)))
	{
	endptr++;
	do
	  {
	  if (lvalue > INT_MAX/1024 || lvalue < INT_MIN/1024)
	    {
	    errno = ERANGE;
	    break;
	    }
	  lvalue *= 1024;
	  }
	while (*(mp += 2));
	}
      }

    if (errno == ERANGE || lvalue > INT_MAX || lvalue < INT_MIN)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
        "absolute value of integer \"%s\" is too large (overflow)", s);

    while (isspace(*endptr)) endptr++;
    if (*endptr)
      extra_chars_error(endptr, inttype, US"integer value for ", name);

    value = (int)lvalue;
    }

  if (data_block)
    *(int *)(US data_block + (long int)ol->value) = value;
  else
    *(int *)ol->value = value;
  break;

  /*  Integer held in K: again, allow formats and suffixes as above. */

  case opt_Kint:
    {
    uschar *endptr;
    errno = 0;
    int_eximarith_t lvalue = strtol(CS s, CSS &endptr, intbase);

    if (endptr == s)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "%sinteger expected for %s",
        inttype, name);

    if (errno != ERANGE && *endptr)
      {
      uschar * mp = US"ZzEePpTtGgMmKk\0";	/* YyZzEePpTtGgMmKk */

      if ((mp = Ustrchr(mp, *endptr)))
	{
	endptr++;
	while (*(mp += 2))
	  {
	  if (lvalue > EXIM_ARITH_MAX/1024 || lvalue < EXIM_ARITH_MIN/1024)
	    {
	    errno = ERANGE;
	    break;
	    }
	  lvalue *= 1024;
	  }
	}
      else
	lvalue = (lvalue + 512)/1024;
      }

    if (errno == ERANGE) log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "absolute value of integer \"%s\" is too large (overflow)", s);

    while (isspace(*endptr)) endptr++;
    if (*endptr != 0)
      extra_chars_error(endptr, inttype, US"integer value for ", name);

    if (data_block)
      *(int_eximarith_t *)(US data_block + (long int)ol->value) = lvalue;
    else
      *(int_eximarith_t *)ol->value = lvalue;
    break;
    }

  /*  Fixed-point number: held to 3 decimal places. */

  case opt_fixed:
  if (sscanf(CS s, "%d%n", &value, &count) != 1)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "fixed-point number expected for %s", name);

  if (value < 0) log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "integer \"%s\" is too large (overflow)", s);

  value *= 1000;

  if (value < 0) log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "integer \"%s\" is too large (overflow)", s);

  /* We get a coverity error here for using count, as it derived
  from the tainted buffer pointed to by s, as parsed by sscanf().
  By the definition of sscanf we must be accessing between start
  and end of s (assuming it is nul-terminated...) so ignore the error.  */
  /* coverity[tainted_data] */
  if (s[count] == '.')
    {
    int d = 100;
    while (isdigit(s[++count]))
      {
      value += (s[count] - '0') * d;
      d /= 10;
      }
    }

  while (isspace(s[count])) count++;

  if (s[count] != 0)
    extra_chars_error(s+count, US"fixed-point value for ", name, US"");

  if (data_block == NULL)
    *((int *)(ol->value)) = value;
  else
    *((int *)(US data_block + (long int)(ol->value))) = value;
  break;

  /* There's a special routine to read time values. */

  case opt_time:
  value = readconf_readtime(s, 0, FALSE);
  if (value < 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "invalid time value for %s",
      name);
  if (data_block == NULL)
    *((int *)(ol->value)) = value;
  else
    *((int *)(US data_block + (long int)(ol->value))) = value;
  break;

  /* A time list is a list of colon-separated times, with the first
  element holding the size of the list and the second the number of
  entries used. */

  case opt_timelist:
    {
    int count = 0;
    int *list = (data_block == NULL)?
      (int *)(ol->value) :
      (int *)(US data_block + (long int)(ol->value));

    if (*s != 0) for (count = 1; count <= list[0] - 2; count++)
      {
      int terminator = 0;
      uschar *snext = Ustrchr(s, ':');
      if (snext != NULL)
        {
        uschar *ss = snext;
        while (ss > s && isspace(ss[-1])) ss--;
        terminator = *ss;
        }
      value = readconf_readtime(s, terminator, FALSE);
      if (value < 0)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "invalid time value for %s",
          name);
      if (count > 1 && value <= list[count])
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
          "time value out of order for %s", name);
      list[count+1] = value;
      if (snext == NULL) break;
      s = snext + 1;
      while (isspace(*s)) s++;
      }

    if (count > list[0] - 2)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "too many time values for %s",
        name);
    if (count > 0 && list[2] == 0) count = 0;
    list[1] = count;
    break;
    }

  case opt_func:
    {
    void (*fn)() = ol->value;
    fn(name, s);
    break;
    }
  }

return TRUE;
}



/*************************************************
*               Print a time value               *
*************************************************/

/*
Argument:  a time value in seconds
Returns:   pointer to a fixed buffer containing the time as a string,
           in readconf_readtime() format
*/

uschar *
readconf_printtime(int t)
{
int s, m, h, d, w;
uschar *p = time_buffer;

if (t < 0)
  {
  *p++ = '-';
  t = -t;
  }

s = t % 60;
t /= 60;
m = t % 60;
t /= 60;
h = t % 24;
t /= 24;
d = t % 7;
w = t/7;

if (w > 0) p += sprintf(CS p, "%dw", w);
if (d > 0) p += sprintf(CS p, "%dd", d);
if (h > 0) p += sprintf(CS p, "%dh", h);
if (m > 0) p += sprintf(CS p, "%dm", m);
if (s > 0 || p == time_buffer) sprintf(CS p, "%ds", s);

return time_buffer;
}



/*************************************************
*      Print an individual option value          *
*************************************************/

/* This is used by the -bP option, so prints to the standard output.
The entire options list is passed in as an argument, because some options come
in pairs - typically uid/gid settings, which can either be explicit numerical
values, or strings to be expanded later. If the numerical value is unset,
search for "*expand_<name>" to see if there is a string equivalent.

Arguments:
  ol             option entry, or NULL for an unknown option
  name           option name
  options_block  NULL for main configuration options; otherwise points to
                   a driver block; if the option doesn't have opt_public
                   set, then options_block->options_block is where the item
                   resides.
  oltop          points to the option list in which ol exists
  last           one more than the offset of the last entry in optop
  no_labels      do not show "foo = " at the start.

Returns:         boolean success
*/

static BOOL
print_ol(optionlist *ol, uschar *name, void *options_block,
  optionlist *oltop, int last, BOOL no_labels)
{
struct passwd *pw;
struct group *gr;
optionlist *ol2;
void *value;
uid_t *uidlist;
gid_t *gidlist;
uschar *s;
uschar name2[64];

if (!ol)
  {
  printf("%s is not a known option\n", name);
  return FALSE;
  }

/* Non-admin callers cannot see options that have been flagged secure by the
"hide" prefix. */

if (!f.admin_user && ol->type & opt_secure)
  {
  if (no_labels)
    printf("%s\n", hidden);
  else
    printf("%s = %s\n", name, hidden);
  return TRUE;
  }

/* Else show the value of the option */

value = ol->value;
if (options_block)
  {
  if (!(ol->type & opt_public))
    options_block = (void *)(((driver_instance *)options_block)->options_block);
  value = (void *)(US options_block + (long int)value);
  }

switch(ol->type & opt_mask)
  {
  case opt_stringptr:
  case opt_rewrite:        /* Show the text value */
    s = *(USS value);
    if (!no_labels) printf("%s = ", name);
    printf("%s\n", s ? string_printing2(s, FALSE) : US"");
    break;

  case opt_int:
    if (!no_labels) printf("%s = ", name);
    printf("%d\n", *((int *)value));
    break;

  case opt_mkint:
    {
    int x = *((int *)value);
    if (x != 0 && (x & 1023) == 0)
      {
      int c = 'K';
      x >>= 10;
      if ((x & 1023) == 0)
        {
        c = 'M';
        x >>= 10;
        }
      if (!no_labels) printf("%s = ", name);
      printf("%d%c\n", x, c);
      }
    else
      {
      if (!no_labels) printf("%s = ", name);
      printf("%d\n", x);
      }
    }
    break;

  case opt_Kint:
    {
    int_eximarith_t x = *((int_eximarith_t *)value);
    if (!no_labels) printf("%s = ", name);
    if (x == 0) printf("0\n");
    else if ((x & ((1<<30)-1)) == 0) printf(PR_EXIM_ARITH "T\n", x >> 30);
    else if ((x & ((1<<20)-1)) == 0) printf(PR_EXIM_ARITH "G\n", x >> 20);
    else if ((x & ((1<<10)-1)) == 0) printf(PR_EXIM_ARITH "M\n", x >> 10);
    else printf(PR_EXIM_ARITH "K\n", x);
    }
    break;

  case opt_octint:
    if (!no_labels) printf("%s = ", name);
    printf("%#o\n", *((int *)value));
    break;

  /* Can be negative only when "unset", in which case integer */

  case opt_fixed:
    {
    int x = *((int *)value);
    int f = x % 1000;
    int d = 100;
    if (x < 0) printf("%s =\n", name); else
      {
      if (!no_labels) printf("%s = ", name);
      printf("%d.", x/1000);
      do
        {
        printf("%d", f/d);
        f %= d;
        d /= 10;
        }
      while (f != 0);
      printf("\n");
      }
    }
    break;

  /* If the numerical value is unset, try for the string value */

  case opt_expand_uid:
    if (! *get_set_flag(name, oltop, last, options_block))
      {
      sprintf(CS name2, "*expand_%.50s", name);
      if ((ol2 = find_option(name2, oltop, last)))
	{
	void *value2 = ol2->value;
	if (options_block)
	  value2 = (void *)(US options_block + (long int)value2);
	s = *(USS value2);
	if (!no_labels) printf("%s = ", name);
	printf("%s\n", s ? string_printing(s) : US"");
	break;
	}
      }

    /* Else fall through */

  case opt_uid:
    if (!no_labels) printf("%s = ", name);
    if (! *get_set_flag(name, oltop, last, options_block))
      printf("\n");
    else
      if ((pw = getpwuid(*((uid_t *)value))))
	printf("%s\n", pw->pw_name);
      else
	printf("%ld\n", (long int)(*((uid_t *)value)));
    break;

  /* If the numerical value is unset, try for the string value */

  case opt_expand_gid:
    if (! *get_set_flag(name, oltop, last, options_block))
      {
      sprintf(CS name2, "*expand_%.50s", name);
      if (  (ol2 = find_option(name2, oltop, last))
	 && (ol2->type & opt_mask) == opt_stringptr)
	{
	void *value2 = ol2->value;
	if (options_block)
	  value2 = (void *)(US options_block + (long int)value2);
	s = *(USS value2);
	if (!no_labels) printf("%s = ", name);
	printf("%s\n", s ? string_printing(s) : US"");
	break;
	}
      }

    /* Else fall through */

  case opt_gid:
    if (!no_labels) printf("%s = ", name);
    if (! *get_set_flag(name, oltop, last, options_block))
      printf("\n");
    else
      if ((gr = getgrgid(*((int *)value))))
	printf("%s\n", gr->gr_name);
      else
	 printf("%ld\n", (long int)(*((int *)value)));
    break;

  case opt_uidlist:
    uidlist = *((uid_t **)value);
    if (!no_labels) printf("%s =", name);
    if (uidlist)
      {
      int i;
      uschar sep = no_labels ? '\0' : ' ';
      for (i = 1; i <= (int)(uidlist[0]); i++)
	{
	uschar *name = NULL;
	if ((pw = getpwuid(uidlist[i]))) name = US pw->pw_name;
	if (sep != '\0') printf("%c", sep);
	if (name) printf("%s", name);
	else printf("%ld", (long int)(uidlist[i]));
	sep = ':';
	}
      }
    printf("\n");
    break;

  case opt_gidlist:
    gidlist = *((gid_t **)value);
    if (!no_labels) printf("%s =", name);
    if (gidlist)
      {
      int i;
      uschar sep = no_labels ? '\0' : ' ';
      for (i = 1; i <= (int)(gidlist[0]); i++)
	{
	uschar *name = NULL;
	if ((gr = getgrgid(gidlist[i]))) name = US gr->gr_name;
	if (sep != '\0') printf("%c", sep);
	if (name) printf("%s", name);
	else printf("%ld", (long int)(gidlist[i]));
	sep = ':';
	}
      }
    printf("\n");
    break;

  case opt_time:
    if (!no_labels) printf("%s = ", name);
    printf("%s\n", readconf_printtime(*((int *)value)));
    break;

  case opt_timelist:
    {
    int i;
    int *list = (int *)value;
    if (!no_labels) printf("%s = ", name);
    for (i = 0; i < list[1]; i++)
      printf("%s%s", i == 0 ? "" : ":", readconf_printtime(list[i+2]));
    printf("\n");
    }
    break;

  case opt_bit:
    printf("%s%s\n", ((*((int *)value)) & (1 << ((ol->type >> 16) & 31)))?
      "" : "no_", name);
    break;

  case opt_expand_bool:
    sprintf(CS name2, "*expand_%.50s", name);
    if ((ol2 = find_option(name2, oltop, last)) && ol2->value)
      {
      void *value2 = ol2->value;
      if (options_block)
	value2 = (void *)(US options_block + (long int)value2);
      s = *(USS value2);
      if (s)
	{
	if (!no_labels) printf("%s = ", name);
	printf("%s\n", string_printing(s));
	break;
	}
      /* s == NULL => string not set; fall through */
      }

    /* Fall through */

  case opt_bool:
  case opt_bool_verify:
  case opt_bool_set:
    printf("%s%s\n", (*((BOOL *)value))? "" : "no_", name);
    break;
  }
return TRUE;
}



/*************************************************
*        Print value from main configuration     *
*************************************************/

/* This function, called as a result of encountering the -bP option,
causes the value of any main configuration variable to be output if the
second argument is NULL. There are some special values:

  all                print all main configuration options
  config_file        print the name of the configuration file
                     (configure_file will still work, for backward
                     compatibility)
  routers            print the routers' configurations
  transports         print the transports' configuration
  authenticators     print the authenticators' configuration
  macros             print the macros' configuration
  router_list        print a list of router names
  transport_list     print a list of transport names
  authenticator_list print a list of authentication mechanism names
  macro_list         print a list of macro names
  +name              print a named list item
  local_scan         print the local_scan options
  config             print the configuration as it is parsed
  environment        print the used execution environment

If the second argument is not NULL, it must be one of "router", "transport",
"authenticator" or "macro" in which case the first argument identifies the
driver whose options are to be printed.

Arguments:
  name        option name if type == NULL; else driver name
  type        NULL or driver type name, as described above
  no_labels   avoid the "foo = " at the start of an item

Returns:      Boolean success
*/

BOOL
readconf_print(uschar *name, uschar *type, BOOL no_labels)
{
BOOL names_only = FALSE;
optionlist *ol;
optionlist *ol2 = NULL;
driver_instance *d = NULL;
macro_item *m;
int size = 0;

if (!type)
  {
  if (*name == '+')
    {
    int i;
    tree_node *t;
    BOOL found = FALSE;
    static uschar *types[] = { US"address", US"domain", US"host",
      US"localpart" };
    static tree_node **anchors[] = { &addresslist_anchor, &domainlist_anchor,
      &hostlist_anchor, &localpartlist_anchor };

    for (i = 0; i < 4; i++)
      if ((t = tree_search(*(anchors[i]), name+1)))
        {
        found = TRUE;
        if (no_labels)
          printf("%s\n", ((namedlist_block *)(t->data.ptr))->string);
        else
          printf("%slist %s = %s\n", types[i], name+1,
            ((namedlist_block *)(t->data.ptr))->string);
        }

    if (!found)
      printf("no address, domain, host, or local part list called \"%s\" "
        "exists\n", name+1);

    return found;
    }

  if (  Ustrcmp(name, "configure_file") == 0
     || Ustrcmp(name, "config_file") == 0)
    {
    printf("%s\n", CS config_main_filename);
    return TRUE;
    }

  if (Ustrcmp(name, "all") == 0)
    {
    for (ol = optionlist_config;
         ol < optionlist_config + nelem(optionlist_config); ol++)
      if (!(ol->type & opt_hidden))
        (void) print_ol(ol, US ol->name, NULL,
		  optionlist_config, nelem(optionlist_config),
		  no_labels);
    return TRUE;
    }

  if (Ustrcmp(name, "local_scan") == 0)
    {
#ifndef LOCAL_SCAN_HAS_OPTIONS
    printf("local_scan() options are not supported\n");
    return FALSE;
#else
    for (ol = local_scan_options;
         ol < local_scan_options + local_scan_options_count; ol++)
      (void) print_ol(ol, US ol->name, NULL, local_scan_options,
		  local_scan_options_count, no_labels);
    return TRUE;
#endif
    }

  if (Ustrcmp(name, "config") == 0)
    {
    print_config(f.admin_user, no_labels);
    return TRUE;
    }

  if (Ustrcmp(name, "routers") == 0)
    {
    type = US"router";
    name = NULL;
    }
  else if (Ustrcmp(name, "transports") == 0)
    {
    type = US"transport";
    name = NULL;
    }
  else if (Ustrcmp(name, "authenticators") == 0)
    {
    type = US"authenticator";
    name = NULL;
    }
  else if (Ustrcmp(name, "macros") == 0)
    {
    type = US"macro";
    name = NULL;
    }
  else if (Ustrcmp(name, "router_list") == 0)
    {
    type = US"router";
    name = NULL;
    names_only = TRUE;
    }
  else if (Ustrcmp(name, "transport_list") == 0)
    {
    type = US"transport";
    name = NULL;
    names_only = TRUE;
    }
  else if (Ustrcmp(name, "authenticator_list") == 0)
    {
    type = US"authenticator";
    name = NULL;
    names_only = TRUE;
    }
  else if (Ustrcmp(name, "macro_list") == 0)
    {
    type = US"macro";
    name = NULL;
    names_only = TRUE;
    }
  else if (Ustrcmp(name, "environment") == 0)
    {
    if (environ)
      {
      uschar ** p;
      for (p = USS environ; *p; p++) ;
      qsort(environ, p - USS environ, sizeof(*p), string_compare_by_pointer);

      for (p = USS environ; *p; p++)
        {
	uschar * q;
        if (no_labels && (q = Ustrchr(*p, '='))) *q  = '\0';
        puts(CS *p);
        }
      }
    return TRUE;
    }

  else
    return print_ol(find_option(name,
      optionlist_config, nelem(optionlist_config)),
      name, NULL, optionlist_config, nelem(optionlist_config), no_labels);
  }

/* Handle the options for a router or transport. Skip options that are flagged
as hidden. Some of these are options with names starting with '*', used for
internal alternative representations of other options (which the printing
function will sort out). Others are synonyms kept for backward compatibility.
*/

if (Ustrcmp(type, "router") == 0)
  {
  d = (driver_instance *)routers;
  ol2 = optionlist_routers;
  size = optionlist_routers_size;
  }
else if (Ustrcmp(type, "transport") == 0)
  {
  d = (driver_instance *)transports;
  ol2 = optionlist_transports;
  size = optionlist_transports_size;
  }
else if (Ustrcmp(type, "authenticator") == 0)
  {
  d = (driver_instance *)auths;
  ol2 = optionlist_auths;
  size = optionlist_auths_size;
  }

else if (Ustrcmp(type, "macro") == 0)
  {
  /* People store passwords in macros and they were previously not available
  for printing.  So we have an admin_users restriction. */
  if (!f.admin_user)
    {
    fprintf(stderr, "exim: permission denied\n");
    return FALSE;
    }
  for (m = macros; m; m = m->next)
    if (!name || Ustrcmp(name, m->name) == 0)
      {
      if (names_only)
        printf("%s\n", CS m->name);
      else if (no_labels)
        printf("%s\n", CS m->replacement);
      else
        printf("%s=%s\n", CS m->name, CS m->replacement);
      if (name)
        return TRUE;
      }
  if (!name) return TRUE;

  printf("%s %s not found\n", type, name);
  return FALSE;
  }

if (names_only)
  {
  for (; d; d = d->next) printf("%s\n", CS d->name);
  return TRUE;
  }

/* Either search for a given driver, or print all of them */

for (; d; d = d->next)
  {
  BOOL rc = FALSE;
  if (!name)
    printf("\n%s %s:\n", d->name, type);
  else if (Ustrcmp(d->name, name) != 0) continue;

  for (ol = ol2; ol < ol2 + size; ol++)
    if (!(ol->type & opt_hidden))
      rc |= print_ol(ol, US ol->name, d, ol2, size, no_labels);

  for (ol = d->info->options;
       ol < d->info->options + *(d->info->options_count); ol++)
    if (!(ol->type & opt_hidden))
      rc |= print_ol(ol, US ol->name, d, d->info->options,
		    *d->info->options_count, no_labels);

  if (name) return rc;
  }
if (!name) return TRUE;

printf("%s %s not found\n", type, name);
return FALSE;
}



/*************************************************
*          Read a named list item                *
*************************************************/

/* This function reads a name and a list (i.e. string). The name is used to
save the list in a tree, sorted by its name. Each entry also has a number,
which can be used for caching tests, but if the string contains any expansion
items other than $key, the number is set negative to inhibit caching. This
mechanism is used for domain, host, and address lists that are referenced by
the "+name" syntax.

Arguments:
  anchorp     points to the tree anchor
  numberp     points to the current number for this tree
  max         the maximum number permitted
  s           the text of the option line, starting immediately after the name
                of the list type
  tname       the name of the list type, for messages

Returns:      nothing
*/

static void
read_named_list(tree_node **anchorp, int *numberp, int max, uschar *s,
  uschar *tname)
{
BOOL forcecache = FALSE;
uschar *ss;
tree_node *t;
namedlist_block *nb = store_get(sizeof(namedlist_block));

if (Ustrncmp(s, "_cache", 6) == 0)
  {
  forcecache = TRUE;
  s += 6;
  }

if (!isspace(*s))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "unrecognized configuration line");

if (*numberp >= max)
 log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "too many named %ss (max is %d)\n",
   tname, max);

while (isspace(*s)) s++;
ss = s;
while (isalnum(*s) || *s == '_') s++;
t = store_get(sizeof(tree_node) + s-ss);
Ustrncpy(t->name, ss, s-ss);
t->name[s-ss] = 0;
while (isspace(*s)) s++;

if (!tree_insertnode(anchorp, t))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "duplicate name \"%s\" for a named %s", t->name, tname);

t->data.ptr = nb;
nb->number = *numberp;
*numberp += 1;

if (*s++ != '=') log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
  "missing '=' after \"%s\"", t->name);
while (isspace(*s)) s++;
nb->string = read_string(s, t->name);
nb->cache_data = NULL;

/* Check the string for any expansions; if any are found, mark this list
uncacheable unless the user has explicited forced caching. */

if (!forcecache && Ustrchr(nb->string, '$') != NULL) nb->number = -1;
}




/*************************************************
*        Unpick data for a rate limit            *
*************************************************/

/* This function is called to unpick smtp_ratelimit_{mail,rcpt} into four
separate values.

Arguments:
  s            string, in the form t,b,f,l
               where t is the threshold (integer)
               b is the initial delay (time)
               f is the multiplicative factor (fixed point)
               k is the maximum time (time)
  threshold    where to store threshold
  base         where to store base in milliseconds
  factor       where to store factor in milliseconds
  limit        where to store limit

Returns:       nothing (panics on error)
*/

static void
unpick_ratelimit(uschar *s, int *threshold, int *base, double *factor,
  int *limit)
{
uschar bstring[16], lstring[16];

if (sscanf(CS s, "%d, %15[0123456789smhdw.], %lf, %15s", threshold, bstring,
    factor, lstring) == 4)
  {
  *base = readconf_readtime(bstring, 0, TRUE);
  *limit = readconf_readtime(lstring, 0, TRUE);
  if (*base >= 0 && *limit >= 0) return;
  }
log_write(0, LOG_MAIN|LOG_PANIC_DIE, "malformed ratelimit data: %s", s);
}




/*************************************************
*       Drop privs for checking TLS config      *
*************************************************/

/* We want to validate TLS options during readconf, but do not want to be
root when we call into the TLS library, in case of library linkage errors
which cause segfaults; before this check, those were always done as the Exim
runtime user and it makes sense to continue with that.

Assumes:  tls_require_ciphers has been set, if it will be
          exim_user has been set, if it will be
          exim_group has been set, if it will be

Returns:  bool for "okay"; false will cause caller to immediately exit.
*/

#ifdef SUPPORT_TLS
static BOOL
tls_dropprivs_validate_require_cipher(BOOL nowarn)
{
const uschar *errmsg;
pid_t pid;
int rc, status;
void (*oldsignal)(int);

/* If TLS will never be used, no point checking ciphers */

if (  !tls_advertise_hosts
   || !*tls_advertise_hosts
   || Ustrcmp(tls_advertise_hosts, ":") == 0
   )
  return TRUE;
else if (!nowarn && !tls_certificate)
  log_write(0, LOG_MAIN,
    "Warning: No server certificate defined; will use a selfsigned one.\n"
    " Suggested action: either install a certificate or change tls_advertise_hosts option");

oldsignal = signal(SIGCHLD, SIG_DFL);

fflush(NULL);
if ((pid = fork()) < 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "fork failed for TLS check");

if (pid == 0)
  {
  /* in some modes, will have dropped privilege already */
  if (!geteuid())
    exim_setugid(exim_uid, exim_gid, FALSE,
        US"calling tls_validate_require_cipher");

  if ((errmsg = tls_validate_require_cipher()))
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
        "tls_require_ciphers invalid: %s", errmsg);
  fflush(NULL);
  _exit(0);
  }

do {
  rc = waitpid(pid, &status, 0);
} while (rc < 0 && errno == EINTR);

DEBUG(D_tls)
  debug_printf("tls_validate_require_cipher child %d ended: status=0x%x\n",
      (int)pid, status);

signal(SIGCHLD, oldsignal);

return status == 0;
}
#endif /* SUPPORT_TLS */




/*************************************************
*         Read main configuration options        *
*************************************************/

/* This function is the first to be called for configuration reading. It
opens the configuration file and reads general configuration settings until
it reaches the end of the configuration section. The file is then left open so
that the remaining configuration data can subsequently be read if needed for
this run of Exim.

The configuration file must be owned either by root or exim, and be writeable
only by root or uid/gid exim. The values for Exim's uid and gid can be changed
in the config file, so the test is done on the compiled in values. A slight
anomaly, to be carefully documented.

The name of the configuration file is taken from a list that is included in the
binary of Exim. It can be altered from the command line, but if that is done,
root privilege is immediately withdrawn unless the caller is root or exim.
The first file on the list that exists is used.

For use on multiple systems that share file systems, first look for a
configuration file whose name has the current node name on the end. If that is
not found, try the generic name. For really contorted configurations, that run
multiple Exims with different uid settings, first try adding the effective uid
before the node name. These complications are going to waste resources on most
systems. Therefore they are available only when requested by compile-time
options. */

void
readconf_main(BOOL nowarn)
{
int sep = 0;
struct stat statbuf;
uschar *s, *filename;
const uschar *list = config_main_filelist;

/* Loop through the possible file names */

while((filename = string_nextinlist(&list, &sep, big_buffer, big_buffer_size)))
  {

  /* Cut out all the fancy processing unless specifically wanted */

  #if defined(CONFIGURE_FILE_USE_NODE) || defined(CONFIGURE_FILE_USE_EUID)
  uschar *suffix = filename + Ustrlen(filename);

  /* Try for the node-specific file if a node name exists */

  #ifdef CONFIGURE_FILE_USE_NODE
  struct utsname uts;
  if (uname(&uts) >= 0)
    {
    #ifdef CONFIGURE_FILE_USE_EUID
    sprintf(CS suffix, ".%ld.%.256s", (long int)original_euid, uts.nodename);
    config_file = Ufopen(filename, "rb");
    if (config_file == NULL)
    #endif  /* CONFIGURE_FILE_USE_EUID */
      {
      sprintf(CS suffix, ".%.256s", uts.nodename);
      config_file = Ufopen(filename, "rb");
      }
    }
  #endif  /* CONFIGURE_FILE_USE_NODE */

  /* Otherwise, try the generic name, possibly with the euid added */

  #ifdef CONFIGURE_FILE_USE_EUID
  if (config_file == NULL)
    {
    sprintf(CS suffix, ".%ld", (long int)original_euid);
    config_file = Ufopen(filename, "rb");
    }
  #endif  /* CONFIGURE_FILE_USE_EUID */

  /* Finally, try the unadorned name */

  if (config_file == NULL)
    {
    *suffix = 0;
    config_file = Ufopen(filename, "rb");
    }
  #else  /* if neither defined */

  /* This is the common case when the fancy processing is not included. */

  config_file = Ufopen(filename, "rb");
  #endif

  /* If the file does not exist, continue to try any others. For any other
  error, break out (and die). */

  if (config_file != NULL || errno != ENOENT) break;
  }

/* On success, save the name for verification; config_filename is used when
logging configuration errors (it changes for .included files) whereas
config_main_filename is the name shown by -bP. Failure to open a configuration
file is a serious disaster. */

if (config_file)
  {
  uschar *last_slash = Ustrrchr(filename, '/');
  config_filename = config_main_filename = string_copy(filename);

  /* The config_main_directory we need for the $config_dir expansion.
  config_main_filename we need for $config_file expansion.
  And config_dir is the directory of the current configuration, used for
  relative .includes. We do need to know it's name, as we change our working
  directory later. */

  if (filename[0] == '/')
    config_main_directory = last_slash == filename ? US"/" : string_copyn(filename, last_slash - filename);
  else
    {
      /* relative configuration file name: working dir + / + basename(filename) */

      uschar buf[PATH_MAX];
      gstring * g;

      if (os_getcwd(buf, PATH_MAX) == NULL)
        {
        perror("exim: getcwd");
        exit(EXIT_FAILURE);
        }
      g = string_cat(NULL, buf);

      /* If the dir does not end with a "/", append one */
      if (g->s[g->ptr-1] != '/')
        g = string_catn(g, US"/", 1);

      /* If the config file contains a "/", extract the directory part */
      if (last_slash)
        g = string_catn(g, filename, last_slash - filename);

      config_main_directory = string_from_gstring(g);
    }
  config_directory = config_main_directory;
  }
else
  {
  if (filename == NULL)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "non-existent configuration file(s): "
      "%s", config_main_filelist);
  else
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s", string_open_failed(errno,
      "configuration file %s", filename));
  }

/* Now, once we found and opened our configuration file, we change the directory
to a safe place. Later we change to $spool_directory. */

if (Uchdir("/") < 0)
  {
  perror("exim: chdir `/': ");
  exit(EXIT_FAILURE);
  }

/* Check the status of the file we have opened, if we have retained root
privileges and the file isn't /dev/null (which *should* be 0666). */

if (f.trusted_config && Ustrcmp(filename, US"/dev/null"))
  {
  if (fstat(fileno(config_file), &statbuf) != 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to stat configuration file %s",
      big_buffer);

  if ((statbuf.st_uid != root_uid                /* owner not root */
       #ifdef CONFIGURE_OWNER
       && statbuf.st_uid != config_uid           /* owner not the special one */
       #endif
         ) ||                                    /* or */
      (statbuf.st_gid != root_gid                /* group not root & */
       #ifdef CONFIGURE_GROUP
       && statbuf.st_gid != config_gid           /* group not the special one */
       #endif
       && (statbuf.st_mode & 020) != 0) ||       /* group writeable  */
                                                 /* or */
      ((statbuf.st_mode & 2) != 0))              /* world writeable  */

    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Exim configuration file %s has the "
      "wrong owner, group, or mode", big_buffer);
  }

/* Process the main configuration settings. They all begin with a lower case
letter. If we see something starting with an upper case letter, it is taken as
a macro definition. */

while ((s = get_config_line()))
  {
  if (config_lineno == 1 && Ustrstr(s, "\xef\xbb\xbf") == s)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "found unexpected BOM (Byte Order Mark)");

  if (isupper(s[0]))
    { if (!macro_read_assignment(s)) exim_exit(EXIT_FAILURE, US""); }

  else if (Ustrncmp(s, "domainlist", 10) == 0)
    read_named_list(&domainlist_anchor, &domainlist_count,
      MAX_NAMED_LIST, s+10, US"domain list");

  else if (Ustrncmp(s, "hostlist", 8) == 0)
    read_named_list(&hostlist_anchor, &hostlist_count,
      MAX_NAMED_LIST, s+8, US"host list");

  else if (Ustrncmp(s, US"addresslist", 11) == 0)
    read_named_list(&addresslist_anchor, &addresslist_count,
      MAX_NAMED_LIST, s+11, US"address list");

  else if (Ustrncmp(s, US"localpartlist", 13) == 0)
    read_named_list(&localpartlist_anchor, &localpartlist_count,
      MAX_NAMED_LIST, s+13, US"local part list");

  else
    (void) readconf_handle_option(s, optionlist_config, optionlist_config_size,
      NULL, US"main option \"%s\" unknown");
  }


/* If local_sender_retain is set, local_from_check must be unset. */

if (local_sender_retain && local_from_check)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "both local_from_check and "
    "local_sender_retain are set; this combination is not allowed");

/* If the timezone string is empty, set it to NULL, implying no TZ variable
wanted. */

if (timezone_string != NULL && *timezone_string == 0) timezone_string = NULL;

/* The max retry interval must not be greater than 24 hours. */

if (retry_interval_max > 24*60*60) retry_interval_max = 24*60*60;

/* remote_max_parallel must be > 0 */

if (remote_max_parallel <= 0) remote_max_parallel = 1;

/* Save the configured setting of freeze_tell, so we can re-instate it at the
start of a new SMTP message. */

freeze_tell_config = freeze_tell;

/* The primary host name may be required for expansion of spool_directory
and log_file_path, so make sure it is set asap. It is obtained from uname(),
but if that yields an unqualified value, make a FQDN by using gethostbyname to
canonize it. Some people like upper case letters in their host names, so we
don't force the case. */

if (primary_hostname == NULL)
  {
  const uschar *hostname;
  struct utsname uts;
  if (uname(&uts) < 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "uname() failed to yield host name");
  hostname = US uts.nodename;

  if (Ustrchr(hostname, '.') == NULL)
    {
    int af = AF_INET;
    struct hostent *hostdata;

    #if HAVE_IPV6
    if (!disable_ipv6 && (dns_ipv4_lookup == NULL ||
         match_isinlist(hostname, CUSS &dns_ipv4_lookup, 0, NULL, NULL,
	    MCL_DOMAIN, TRUE, NULL) != OK))
      af = AF_INET6;
    #else
    af = AF_INET;
    #endif

    for (;;)
      {
      #if HAVE_IPV6
        #if HAVE_GETIPNODEBYNAME
        int error_num;
        hostdata = getipnodebyname(CS hostname, af, 0, &error_num);
        #else
        hostdata = gethostbyname2(CS hostname, af);
        #endif
      #else
      hostdata = gethostbyname(CS hostname);
      #endif

      if (hostdata != NULL)
        {
        hostname = US hostdata->h_name;
        break;
        }

      if (af == AF_INET) break;
      af = AF_INET;
      }
    }

  primary_hostname = string_copy(hostname);
  }

/* Set up default value for smtp_active_hostname */

smtp_active_hostname = primary_hostname;

/* If spool_directory wasn't set in the build-time configuration, it must have
got set above. Of course, writing to the log may not work if log_file_path is
not set, but it will at least get to syslog or somewhere, with any luck. */

if (*spool_directory == 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "spool_directory undefined: cannot "
    "proceed");

/* Expand the spool directory name; it may, for example, contain the primary
host name. Same comment about failure. */

s = expand_string(spool_directory);
if (s == NULL)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to expand spool_directory "
    "\"%s\": %s", spool_directory, expand_string_message);
spool_directory = s;

/* Expand log_file_path, which must contain "%s" in any component that isn't
the null string or "syslog". It is also allowed to contain one instance of %D
or %M. However, it must NOT contain % followed by anything else. */

if (*log_file_path != 0)
  {
  const uschar *ss, *sss;
  int sep = ':';                       /* Fixed for log file path */
  s = expand_string(log_file_path);
  if (s == NULL)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to expand log_file_path "
      "\"%s\": %s", log_file_path, expand_string_message);

  ss = s;
  while ((sss = string_nextinlist(&ss,&sep,big_buffer,big_buffer_size)) != NULL)
    {
    uschar *t;
    if (sss[0] == 0 || Ustrcmp(sss, "syslog") == 0) continue;
    t = Ustrstr(sss, "%s");
    if (t == NULL)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "log_file_path \"%s\" does not "
        "contain \"%%s\"", sss);
    *t = 'X';
    t = Ustrchr(sss, '%');
    if (t != NULL)
      {
      if ((t[1] != 'D' && t[1] != 'M') || Ustrchr(t+2, '%') != NULL)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "log_file_path \"%s\" contains "
          "unexpected \"%%\" character", s);
      }
    }

  log_file_path = s;
  }

/* Interpret syslog_facility into an integer argument for 'ident' param to
openlog(). Default is LOG_MAIL set in globals.c. Allow the user to omit the
leading "log_". */

if (syslog_facility_str)
  {
  int i;
  uschar *s = syslog_facility_str;

  if ((Ustrlen(syslog_facility_str) >= 4) &&
        (strncmpic(syslog_facility_str, US"log_", 4) == 0))
    s += 4;

  for (i = 0; i < syslog_list_size; i++)
    if (strcmpic(s, syslog_list[i].name) == 0)
      {
      syslog_facility = syslog_list[i].value;
      break;
      }

  if (i >= syslog_list_size)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "failed to interpret syslog_facility \"%s\"", syslog_facility_str);
  }

/* Expand pid_file_path */

if (*pid_file_path != 0)
  {
  if (!(s = expand_string(pid_file_path)))
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to expand pid_file_path "
      "\"%s\": %s", pid_file_path, expand_string_message);
  pid_file_path = s;
  }

/* Set default value of process_log_path */

if (!process_log_path || *process_log_path =='\0')
  process_log_path = string_sprintf("%s/exim-process.info", spool_directory);

/* Compile the regex for matching a UUCP-style "From_" line in an incoming
message. */

regex_From = regex_must_compile(uucp_from_pattern, FALSE, TRUE);

/* Unpick the SMTP rate limiting options, if set */

if (smtp_ratelimit_mail)
  unpick_ratelimit(smtp_ratelimit_mail, &smtp_rlm_threshold,
    &smtp_rlm_base, &smtp_rlm_factor, &smtp_rlm_limit);

if (smtp_ratelimit_rcpt)
  unpick_ratelimit(smtp_ratelimit_rcpt, &smtp_rlr_threshold,
    &smtp_rlr_base, &smtp_rlr_factor, &smtp_rlr_limit);

/* The qualify domains default to the primary host name */

if (!qualify_domain_sender)
  qualify_domain_sender = primary_hostname;
if (!qualify_domain_recipient)
  qualify_domain_recipient = qualify_domain_sender;

/* Setting system_filter_user in the configuration sets the gid as well if a
name is given, but a numerical value does not. */

if (system_filter_uid_set && !system_filter_gid_set)
  {
  struct passwd *pw = getpwuid(system_filter_uid);
  if (!pw)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Failed to look up uid %ld",
      (long int)system_filter_uid);
  system_filter_gid = pw->pw_gid;
  system_filter_gid_set = TRUE;
  }

/* If the errors_reply_to field is set, check that it is syntactically valid
and ensure it contains a domain. */

if (errors_reply_to)
  {
  uschar *errmess;
  int start, end, domain;
  uschar *recipient = parse_extract_address(errors_reply_to, &errmess,
    &start, &end, &domain, FALSE);

  if (!recipient)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "error in errors_reply_to (%s): %s", errors_reply_to, errmess);

  if (domain == 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "errors_reply_to (%s) does not contain a domain", errors_reply_to);
  }

/* If smtp_accept_queue or smtp_accept_max_per_host is set, then
smtp_accept_max must also be set. */

if (smtp_accept_max == 0 &&
    (smtp_accept_queue > 0 || smtp_accept_max_per_host != NULL))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "smtp_accept_max must be set if smtp_accept_queue or "
    "smtp_accept_max_per_host is set");

/* Set up the host number if anything is specified. It is an expanded string
so that it can be computed from the host name, for example. We do this last
so as to ensure that everything else is set up before the expansion. */

if (host_number_string)
  {
  long int n;
  uschar *end;
  uschar *s = expand_string(host_number_string);

  if (!s)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE,
        "failed to expand localhost_number \"%s\": %s",
        host_number_string, expand_string_message);
  n = Ustrtol(s, &end, 0);
  while (isspace(*end)) end++;
  if (*end != 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "localhost_number value is not a number: %s", s);
  if (n > LOCALHOST_MAX)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "localhost_number is greater than the maximum allowed value (%d)",
        LOCALHOST_MAX);
  host_number = n;
  }

#ifdef SUPPORT_TLS
/* If tls_verify_hosts is set, tls_verify_certificates must also be set */

if ((tls_verify_hosts || tls_try_verify_hosts) && !tls_verify_certificates)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "tls_%sverify_hosts is set, but tls_verify_certificates is not set",
    tls_verify_hosts ? "" : "try_");

/* This also checks that the library linkage is working and we can call
routines in it, so call even if tls_require_ciphers is unset */
if (!tls_dropprivs_validate_require_cipher(nowarn))
  exit(1);

/* Magic number: at time of writing, 1024 has been the long-standing value
used by so many clients, and what Exim used to use always, that it makes
sense to just min-clamp this max-clamp at that. */
if (tls_dh_max_bits < 1024)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "tls_dh_max_bits is too small, must be at least 1024 for interop");

/* If openssl_options is set, validate it */
if (openssl_options)
  {
# ifdef USE_GNUTLS
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "openssl_options is set but we're using GnuTLS");
# else
  long dummy;
  if (!tls_openssl_options_parse(openssl_options, &dummy))
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "openssl_options parse error: %s", openssl_options);
# endif
  }
#endif	/*SUPPORT_TLS*/

if (!nowarn && !keep_environment && environ && *environ)
  log_write(0, LOG_MAIN,
      "Warning: purging the environment.\n"
      " Suggested action: use keep_environment.");
}



/*************************************************
*          Initialize one driver                 *
*************************************************/

/* This is called once the driver's generic options, if any, have been read.
We can now find the driver, set up defaults for the private options, and
unset any "set" bits in the private options table (which might have been
set by another incarnation of the same driver).

Arguments:
  d                   pointer to driver instance block, with generic
                        options filled in
  drivers_available   vector of available drivers
  size_of_info        size of each block in drivers_available
  class               class of driver, for error message

Returns:              pointer to the driver info block
*/

static driver_info *
init_driver(driver_instance *d, driver_info *drivers_available,
  int size_of_info, uschar *class)
{
driver_info *dd;

for (dd = drivers_available; dd->driver_name[0] != 0;
     dd = (driver_info *)((US dd) + size_of_info))
  {
  if (Ustrcmp(d->driver_name, dd->driver_name) == 0)
    {
    int i;
    int len = dd->options_len;
    d->info = dd;
    d->options_block = store_get(len);
    memcpy(d->options_block, dd->options_block, len);
    for (i = 0; i < *(dd->options_count); i++)
      dd->options[i].type &= ~opt_set;
    return dd;
    }
  }

log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
  "%s %s: cannot find %s driver \"%s\"", class, d->name, class, d->driver_name);

return NULL;   /* never obeyed */
}




/*************************************************
*             Initialize driver list             *
*************************************************/

/* This function is called for routers, transports, and authentication
mechanisms. It reads the data from the current point in the configuration file
up to the end of the section, and sets up a chain of instance blocks according
to the file's contents. The file will already have been opened by a call to
readconf_main, and must be left open for subsequent reading of further data.

Any errors cause a panic crash. Note that the blocks with names driver_info and
driver_instance must map the first portions of all the _info and _instance
blocks for this shared code to work.

Arguments:
  class                      "router", "transport", or "authenticator"
  anchor                     &routers, &transports, &auths
  drivers_available          available drivers
  size_of_info               size of each info block
  instance_default           points to default data for an instance
  instance_size              size of instance block
  driver_optionlist          generic option list
  driver_optionlist_count    count of generic option list

Returns:                     nothing
*/

void
readconf_driver_init(
  uschar *class,
  driver_instance **anchor,
  driver_info *drivers_available,
  int size_of_info,
  void *instance_default,
  int  instance_size,
  optionlist *driver_optionlist,
  int  driver_optionlist_count)
{
driver_instance **p = anchor;
driver_instance *d = NULL;
uschar *buffer;

while ((buffer = get_config_line()) != NULL)
  {
  uschar name[64];
  uschar *s;

  /* Read the first name on the line and test for the start of a new driver. A
  macro definition indicates the end of the previous driver. If this isn't the
  start of a new driver, the line will be re-read. */

  s = readconf_readname(name, sizeof(name), buffer);

  /* Handle macro definition, first finishing off the initialization of the
  previous driver, if any. */

  if (isupper(*name) && *s == '=')
    {
    if (d)
      {
      if (!d->driver_name)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
          "no driver defined for %s \"%s\"", class, d->name);
      (d->info->init)(d);
      d = NULL;
      }
    if (!macro_read_assignment(buffer)) exim_exit(EXIT_FAILURE, US"");
    continue;
    }

  /* If the line starts with a name terminated by a colon, we are at the
  start of the definition of a new driver. The rest of the line must be
  blank. */

  if (*s++ == ':')
    {
    int i;

    /* Finish off initializing the previous driver. */

    if (d)
      {
      if (!d->driver_name)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
          "no driver defined for %s \"%s\"", class, d->name);
      (d->info->init)(d);
      }

    /* Check that we haven't already got a driver of this name */

    for (d = *anchor; d; d = d->next)
      if (Ustrcmp(name, d->name) == 0)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
          "there are two %ss called \"%s\"", class, name);

    /* Set up a new driver instance data block on the chain, with
    its default values installed. */

    d = store_get(instance_size);
    memcpy(d, instance_default, instance_size);
    *p = d;
    p = &d->next;
    d->name = string_copy(name);

    /* Clear out the "set" bits in the generic options */

    for (i = 0; i < driver_optionlist_count; i++)
      driver_optionlist[i].type &= ~opt_set;

    /* Check nothing more on this line, then do the next loop iteration. */

    while (isspace(*s)) s++;
    if (*s != 0) extra_chars_error(s, US"driver name ", name, US"");
    continue;
    }

  /* Not the start of a new driver. Give an error if we have not set up a
  current driver yet. */

  if (!d)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "%s name missing", class);

  /* First look to see if this is a generic option; if it is "driver",
  initialize the driver. If is it not a generic option, we can look for a
  private option provided that the driver has been previously set up. */

  if (readconf_handle_option(buffer, driver_optionlist,
        driver_optionlist_count, d, NULL))
    {
    if (!d->info && d->driver_name)
      init_driver(d, drivers_available, size_of_info, class);
    }

  /* Handle private options - pass the generic block because some may
  live therein. A flag with each option indicates if it is in the public
  block. */

  else if (d->info)
    readconf_handle_option(buffer, d->info->options,
      *(d->info->options_count), d, US"option \"%s\" unknown");

  /* The option is not generic and the driver name has not yet been given. */

  else log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "option \"%s\" unknown "
    "(\"driver\" must be specified before any private options)", name);
  }

/* Run the initialization function for the final driver. */

if (d)
  {
  if (!d->driver_name)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "no driver defined for %s \"%s\"", class, d->name);
  (d->info->init)(d);
  }
}



/*************************************************
*            Check driver dependency             *
*************************************************/

/* This function is passed a driver instance and a string. It checks whether
any of the string options for the driver contains the given string as an
expansion variable.

Arguments:
  d        points to a driver instance block
  s        the string to search for

Returns:   TRUE if a dependency is found
*/

BOOL
readconf_depends(driver_instance *d, uschar *s)
{
int count = *(d->info->options_count);
optionlist *ol;
uschar *ss;

for (ol = d->info->options; ol < d->info->options + count; ol++)
  {
  void *options_block;
  uschar *value;
  int type = ol->type & opt_mask;
  if (type != opt_stringptr) continue;
  options_block = ((ol->type & opt_public) == 0)? d->options_block : (void *)d;
  value = *(uschar **)(US options_block + (long int)(ol->value));
  if (value != NULL && (ss = Ustrstr(value, s)) != NULL)
    {
    if (ss <= value || (ss[-1] != '$' && ss[-1] != '{') ||
      isalnum(ss[Ustrlen(s)])) continue;
    DEBUG(D_transport) debug_printf("driver %s: \"%s\" option depends on %s\n",
      d->name, ol->name, s);
    return TRUE;
    }
  }

DEBUG(D_transport) debug_printf("driver %s does not depend on %s\n", d->name, s);
return FALSE;
}




/*************************************************
*      Decode an error type for retries          *
*************************************************/

/* This function is global because it is also called from the main
program when testing retry information. It decodes strings such as "quota_7d"
into numerical error codes.

Arguments:
  pp           points to start of text
  p            points past end of text
  basic_errno  points to an int to receive the main error number
  more_errno   points to an int to receive the secondary error data

Returns:       NULL if decoded correctly; else points to error text
*/

uschar *
readconf_retry_error(const uschar *pp, const uschar *p,
  int *basic_errno, int *more_errno)
{
int len;
const uschar *q = pp;
while (q < p && *q != '_') q++;
len = q - pp;

if (len == 5 && strncmpic(pp, US"quota", len) == 0)
  {
  *basic_errno = ERRNO_EXIMQUOTA;
  if (q != p && (*more_errno = readconf_readtime(q+1, *p, FALSE)) < 0)
      return US"bad time value";
  }

else if (len == 7 && strncmpic(pp, US"refused", len) == 0)
  {
  *basic_errno = ECONNREFUSED;
  if (q != p)
    {
    if (strncmpic(q+1, US"MX", p-q-1) == 0) *more_errno = 'M';
    else if (strncmpic(q+1, US"A", p-q-1) == 0) *more_errno = 'A';
    else return US"A or MX expected after \"refused\"";
    }
  }

else if (len == 7 && strncmpic(pp, US"timeout", len) == 0)
  {
  *basic_errno = ETIMEDOUT;
  if (q != p)
    {
    int i;
    int xlen = p - q - 1;
    const uschar *x = q + 1;

    static uschar *extras[] =
      { US"A", US"MX", US"connect", US"connect_A",  US"connect_MX" };
    static int values[] =
      { 'A',   'M',    RTEF_CTOUT,  RTEF_CTOUT|'A', RTEF_CTOUT|'M' };

    for (i = 0; i < nelem(extras); i++)
      if (strncmpic(x, extras[i], xlen) == 0)
        {
        *more_errno = values[i];
        break;
        }

    if (i >= nelem(extras))
      if (strncmpic(x, US"DNS", xlen) == 0)
        log_write(0, LOG_MAIN|LOG_PANIC, "\"timeout_dns\" is no longer "
          "available in retry rules (it has never worked) - treated as "
          "\"timeout\"");
      else
        return US"\"A\", \"MX\", or \"connect\" expected after \"timeout\"";
    }
  }

else if (strncmpic(pp, US"mail_4", 6) == 0 ||
         strncmpic(pp, US"rcpt_4", 6) == 0 ||
         strncmpic(pp, US"data_4", 6) == 0)
  {
  BOOL bad = FALSE;
  int x = 255;                           /* means "any 4xx code" */
  if (p != pp + 8) bad = TRUE; else
    {
    int a = pp[6], b = pp[7];
    if (isdigit(a))
      {
      x = (a - '0') * 10;
      if (isdigit(b)) x += b - '0';
      else if (b == 'x') x += 100;
      else bad = TRUE;
      }
    else if (a != 'x' || b != 'x') bad = TRUE;
    }

  if (bad)
    return string_sprintf("%.4s_4 must be followed by xx, dx, or dd, where "
      "x is literal and d is any digit", pp);

  *basic_errno = *pp == 'm' ? ERRNO_MAIL4XX :
                 *pp == 'r' ? ERRNO_RCPT4XX : ERRNO_DATA4XX;
  *more_errno = x << 8;
  }

else if (len == 4 && strncmpic(pp, US"auth", len) == 0 &&
         strncmpic(q+1, US"failed", p-q-1) == 0)
  *basic_errno = ERRNO_AUTHFAIL;

else if (strncmpic(pp, US"lost_connection", p - pp) == 0)
  *basic_errno = ERRNO_SMTPCLOSED;

else if (strncmpic(pp, US"tls_required", p - pp) == 0)
  *basic_errno = ERRNO_TLSREQUIRED;

else if (strncmpic(pp, US"lookup", p - pp) == 0)
  *basic_errno = ERRNO_UNKNOWNHOST;

else if (len != 1 || Ustrncmp(pp, "*", 1) != 0)
  return string_sprintf("unknown or malformed retry error \"%.*s\"", (int) (p-pp), pp);

return NULL;
}




/*************************************************
*                Read retry information          *
*************************************************/

/* Each line of retry information contains:

.  A domain name pattern or an address pattern;

.  An error name, possibly with additional data, or *;

.  An optional sequence of retry items, each consisting of an identifying
   letter, a cutoff time, and optional parameters.

All this is decoded and placed into a control block. */


/* Subroutine to read an argument, preceded by a comma and terminated
by comma, semicolon, whitespace, or newline. The types are: 0 = time value,
1 = fixed point number (returned *1000).

Arguments:
  paddr     pointer to pointer to current character; updated
  type      0 => read a time; 1 => read a fixed point number

Returns:    time in seconds or fixed point number * 1000
*/

static int
retry_arg(const uschar **paddr, int type)
{
const uschar *p = *paddr;
const uschar *pp;

if (*p++ != ',') log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "comma expected");

while (isspace(*p)) p++;
pp = p;
while (isalnum(*p) || (type == 1 && *p == '.')) p++;

if (*p != 0 && !isspace(*p) && *p != ',' && *p != ';')
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "comma or semicolon expected");

*paddr = p;
switch (type)
  {
  case 0: return readconf_readtime(pp, *p, FALSE);
  case 1: return readconf_readfixed(pp, *p);
  }
return 0;    /* Keep picky compilers happy */
}

/* The function proper */

void
readconf_retries(void)
{
retry_config **chain = &retries;
retry_config *next;
const uschar *p;

while ((p = get_config_line()))
  {
  retry_rule **rchain;
  const uschar *pp;
  uschar *error;

  next = store_get(sizeof(retry_config));
  next->next = NULL;
  *chain = next;
  chain = &(next->next);
  next->basic_errno = next->more_errno = 0;
  next->senders = NULL;
  next->rules = NULL;
  rchain = &(next->rules);

  next->pattern = string_dequote(&p);
  while (isspace(*p)) p++;
  pp = p;
  while (mac_isgraph(*p)) p++;
  if (p - pp <= 0) log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
    "missing error type in retry rule");

  /* Test error names for things we understand. */

  if ((error = readconf_retry_error(pp, p, &next->basic_errno,
       &next->more_errno)))
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "%s", error);

  /* There may be an optional address list of senders to be used as another
  constraint on the rule. This was added later, so the syntax is a bit of a
  fudge. Anything that is not a retry rule starting "F," or "G," is treated as
  an address list. */

  while (isspace(*p)) p++;
  if (Ustrncmp(p, "senders", 7) == 0)
    {
    p += 7;
    while (isspace(*p)) p++;
    if (*p++ != '=') log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "\"=\" expected after \"senders\" in retry rule");
    while (isspace(*p)) p++;
    next->senders = string_dequote(&p);
    }

  /* Now the retry rules. Keep the maximum timeout encountered. */

  while (isspace(*p)) p++;

  while (*p != 0)
    {
    retry_rule *rule = store_get(sizeof(retry_rule));
    *rchain = rule;
    rchain = &(rule->next);
    rule->next = NULL;
    rule->rule = toupper(*p++);
    rule->timeout = retry_arg(&p, 0);
    if (rule->timeout > retry_maximum_timeout)
      retry_maximum_timeout = rule->timeout;

    switch (rule->rule)
      {
      case 'F':   /* Fixed interval */
	rule->p1 = retry_arg(&p, 0);
	break;

      case 'G':   /* Geometrically increasing intervals */
      case 'H':   /* Ditto, but with randomness */
	rule->p1 = retry_arg(&p, 0);
	rule->p2 = retry_arg(&p, 1);
	break;

      default:
	log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "unknown retry rule letter");
	break;
      }

    if (rule->timeout <= 0 || rule->p1 <= 0 ||
          (rule->rule != 'F' && rule->p2 < 1000))
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
        "bad parameters for retry rule");

    while (isspace(*p)) p++;
    if (*p == ';')
      {
      p++;
      while (isspace(*p)) p++;
      }
    else if (*p != 0)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "semicolon expected");
    }
  }
}



/*************************************************
*         Initialize authenticators              *
*************************************************/

/* Read the authenticators section of the configuration file.

Arguments:   none
Returns:     nothing
*/

static void
auths_init(void)
{
auth_instance *au, *bu;
#ifdef EXPERIMENTAL_PIPE_CONNECT
int nauths = 0;
#endif

readconf_driver_init(US"authenticator",
  (driver_instance **)(&auths),      /* chain anchor */
  (driver_info *)auths_available,    /* available drivers */
  sizeof(auth_info),                 /* size of info block */
  &auth_defaults,                    /* default values for generic options */
  sizeof(auth_instance),             /* size of instance block */
  optionlist_auths,                  /* generic options */
  optionlist_auths_size);

for (au = auths; au; au = au->next)
  {
  if (!au->public_name)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG, "no public name specified for "
      "the %s authenticator", au->name);

  for (bu = au->next; bu; bu = bu->next)
    if (strcmpic(au->public_name, bu->public_name) == 0)
      if ((au->client && bu->client) || (au->server && bu->server))
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG, "two %s authenticators "
          "(%s and %s) have the same public name (%s)",
          au->client ? US"client" : US"server", au->name, bu->name,
          au->public_name);
#ifdef EXPERIMENTAL_PIPE_CONNECT
  nauths++;
#endif
  }
#ifdef EXPERIMENTAL_PIPE_CONNECT
f.smtp_in_early_pipe_no_auth = nauths > 16;
#endif
}




/*************************************************
*             Read ACL information               *
*************************************************/

/* If this run of Exim is not doing something that involves receiving a
message, we can just skip over the ACL information. No need to parse it.

First, we have a function for acl_read() to call back to get the next line. We
need to remember the line we passed, because at the end it will contain the
name of the next ACL. */

static uschar *acl_line;

static uschar *
acl_callback(void)
{
acl_line = get_config_line();
return acl_line;
}


/* Now the main function:

Arguments:    none
Returns:      nothing
*/

static void
readconf_acl(void)
{
uschar *p;

/* Read each ACL and add it into the tree. Macro (re)definitions are allowed
between ACLs. */

acl_line = get_config_line();

while(acl_line)
  {
  uschar name[64];
  tree_node *node;
  uschar *error;

  p = readconf_readname(name, sizeof(name), acl_line);
  if (isupper(*name) && *p == '=')
    {
    if (!macro_read_assignment(acl_line)) exim_exit(EXIT_FAILURE, US"");
    acl_line = get_config_line();
    continue;
    }

  if (*p != ':' || name[0] == 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "missing or malformed ACL name");

  node = store_get(sizeof(tree_node) + Ustrlen(name));
  Ustrcpy(node->name, name);
  if (!tree_insertnode(&acl_anchor, node))
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "there are two ACLs called \"%s\"", name);

  node->data.ptr = acl_read(acl_callback, &error);

  if (node->data.ptr == NULL && error != NULL)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "error in ACL: %s", error);
  }
}



/*************************************************
*     Read configuration for local_scan()        *
*************************************************/

/* This function is called after "begin local_scan" is encountered in the
configuration file. If the local_scan() function allows for configuration
options, we can process them. Otherwise, we expire in a panic.

Arguments:  none
Returns:    nothing
*/

static void
local_scan_init(void)
{
#ifndef LOCAL_SCAN_HAS_OPTIONS
log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN, "local_scan() options not supported: "
  "(LOCAL_SCAN_HAS_OPTIONS not defined in Local/Makefile)");
#else

uschar *p;
while ((p = get_config_line()))
  {
  (void) readconf_handle_option(p, local_scan_options, local_scan_options_count,
    NULL, US"local_scan option \"%s\" unknown");
  }
#endif
}



/*************************************************
*     Read rest of configuration (after main)    *
*************************************************/

/* This function reads the rest of the runtime configuration, after the main
configuration. It is called only when actually needed. Each subsequent section
of the configuration starts with a line of the form

  begin name

where the name is "routers", "transports", etc. A section is terminated by
hitting the next "begin" line, and the next name is left in next_section.
Because it may confuse people as to whether the names are singular or plural,
we add "s" if it's missing. There is always enough room in next_section for
this. This function is basically just a switch.

Arguments:   none
Returns:     nothing
*/

static uschar *section_list[] = {
  US"acls",
  US"authenticators",
  US"local_scans",
  US"retrys",
  US"rewrites",
  US"routers",
  US"transports"};

void
readconf_rest(void)
{
int had = 0;

while(next_section[0] != 0)
  {
  int bit;
  int first = 0;
  int last = nelem(section_list);
  int mid = last/2;
  int n = Ustrlen(next_section);

  if (tolower(next_section[n-1]) != 's') Ustrcpy(next_section+n, "s");

  for (;;)
    {
    int c = strcmpic(next_section, section_list[mid]);
    if (c == 0) break;
    if (c > 0) first = mid + 1; else last = mid;
    if (first >= last)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
        "\"%.*s\" is not a known configuration section name", n, next_section);
    mid = (last + first)/2;
    }

  bit = 1 << mid;
  if (((had ^= bit) & bit) == 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_IN,
      "\"%.*s\" section is repeated in the configuration file", n,
        next_section);

  switch(mid)
    {
    case 0: readconf_acl(); break;
    case 1: auths_init(); break;
    case 2: local_scan_init(); break;
    case 3: readconf_retries(); break;
    case 4: readconf_rewrites(); break;
    case 5: route_init(); break;
    case 6: transport_init(); break;
    }
  }

(void)fclose(config_file);
}

/* Init the storage for the pre-parsed config lines */
void
readconf_save_config(const uschar *s)
{
save_config_line(string_sprintf("# Exim Configuration (%s)",
  f.running_in_test_harness ? US"X" : s));
}

static void
save_config_position(const uschar *file, int line)
{
save_config_line(string_sprintf("# %d \"%s\"", line, file));
}

/* Append a pre-parsed logical line to the config lines store,
this operates on a global (static) list that holds all the pre-parsed
config lines, we do no further processing here, output formatting and
honouring of <hide> or macros will be done during output */

static void
save_config_line(const uschar* line)
{
static config_line_item *current;
config_line_item *next;

next = (config_line_item*) store_get(sizeof(config_line_item));
next->line = string_copy(line);
next->next = NULL;

if (!config_lines) config_lines = next;
else current->next = next;

current = next;
}

/* List the parsed config lines, care about nice formatting and
hide the <hide> values unless we're the admin user */
void
print_config(BOOL admin, BOOL terse)
{
config_line_item *i;
const int TS = terse ? 0 : 2;
int indent = 0;

for (i = config_lines; i; i = i->next)
  {
  uschar *current;
  uschar *p;

  /* skip over to the first non-space */
  for (current = i->line; *current && isspace(*current); ++current)
    ;

  if (*current == '\0')
    continue;

  /* Collapse runs of spaces. We stop this if we encounter one of the
   * following characters: "'$, as this may indicate careful formatting */
  for (p = current; *p; ++p)
    {
    uschar *next;
    if (!isspace(*p)) continue;
    if (*p != ' ') *p = ' ';

    for (next = p; isspace(*next); ++next)
      ;

    if (next - p > 1)
      memmove(p+1, next, Ustrlen(next)+1);

    if (*next == '"' || *next == '\'' || *next == '$')
      break;
    }

  /* # lines */
  if (current[0] == '#')
    puts(CCS current);

  /* begin lines are left aligned */
  else if (Ustrncmp(current, "begin", 5) == 0 && isspace(current[5]))
    {
    if (!terse) puts("");
    puts(CCS current);
    indent = TS;
    }

  /* router/acl/transport block names */
  else if (current[Ustrlen(current)-1] == ':' && !Ustrchr(current, '='))
    {
    if (!terse) puts("");
    printf("%*s%s\n", TS, "", current);
    indent = 2 * TS;
    }

  /* hidden lines (all MACROS or lines prefixed with "hide") */
  else if (  !admin
	  && (  isupper(*current)
	     || Ustrncmp(current, "hide", 4) == 0 && isspace(current[4])
	     )
	  )
    {
    if ((p = Ustrchr(current, '=')))
      {
      *p = '\0';
      printf("%*s%s= %s\n", indent, "", current, hidden);
      }
    /* e.g.: hide split_spool_directory */
    else
      printf("%*s\n", indent, hidden);
    }

  else
    /* rest is public */
    printf("%*s%s\n", indent, "", current);
  }
}

#endif	/*!MACRO_PREDEF*/
/* vi: aw ai sw=2
*/
/* End of readconf.c */
