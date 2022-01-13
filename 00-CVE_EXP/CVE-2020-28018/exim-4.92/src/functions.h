/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


/* Prototypes for functions that appear in various modules. Gathered together
to avoid having a lot of tiddly little headers with only a couple of lines in
them. However, some functions that are used (or not used) by utility programs
are in in fact in separate headers. */


#ifdef EXIM_PERL
extern gstring *call_perl_cat(gstring *, uschar **, uschar *,
                 uschar **) WARN_UNUSED_RESULT;
extern void    cleanup_perl(void);
extern uschar *init_perl(uschar *);
#endif


#ifdef SUPPORT_TLS
extern const char *
               std_dh_prime_default(void);
extern const char *
               std_dh_prime_named(const uschar *);

extern uschar * tls_cert_crl_uri(void *, uschar * mod);
extern uschar * tls_cert_ext_by_oid(void *, uschar *, int);
extern uschar * tls_cert_issuer(void *, uschar * mod);
extern uschar * tls_cert_not_before(void *, uschar * mod);
extern uschar * tls_cert_not_after(void *, uschar * mod);
extern uschar * tls_cert_ocsp_uri(void *, uschar * mod);
extern uschar * tls_cert_serial_number(void *, uschar * mod);
extern uschar * tls_cert_signature(void *, uschar * mod);
extern uschar * tls_cert_signature_algorithm(void *, uschar * mod);
extern uschar * tls_cert_subject(void *, uschar * mod);
extern uschar * tls_cert_subject_altname(void *, uschar * mod);
extern uschar * tls_cert_version(void *, uschar * mod);

extern uschar * tls_cert_der_b64(void * cert);
extern uschar * tls_cert_fprt_md5(void *);
extern uschar * tls_cert_fprt_sha1(void *);
extern uschar * tls_cert_fprt_sha256(void *);

extern void *  tls_client_start(int, host_item *, address_item *,
		 transport_instance *,
# ifdef SUPPORT_DANE
		dns_answer *,
# endif
		tls_support *, uschar **);
extern void    tls_close(void *, int);
extern BOOL    tls_could_read(void);
extern int     tls_export_cert(uschar *, size_t, void *);
extern int     tls_feof(void);
extern int     tls_ferror(void);
extern void    tls_free_cert(void **);
extern int     tls_getc(unsigned);
extern uschar *tls_getbuf(unsigned *);
extern void    tls_get_cache(void);
extern int     tls_import_cert(const uschar *, void **);
extern int     tls_read(void *, uschar *, size_t);
extern int     tls_server_start(const uschar *, uschar **);
extern BOOL    tls_smtp_buffered(void);
extern int     tls_ungetc(int);
extern int     tls_write(void *, const uschar *, size_t, BOOL);
extern uschar *tls_validate_require_cipher(void);
extern void    tls_version_report(FILE *);
# ifndef USE_GNUTLS
extern BOOL    tls_openssl_options_parse(uschar *, long *);
# endif
extern uschar * tls_field_from_dn(uschar *, const uschar *);
extern BOOL    tls_is_name_for_cert(const uschar *, void *);

# ifdef SUPPORT_DANE
extern int     tlsa_lookup(const host_item *, dns_answer *, BOOL);
# endif

#endif	/*SUPPORT_TLS*/


/* Everything else... */

extern acl_block *acl_read(uschar *(*)(void), uschar **);
extern int     acl_check(int, uschar *, uschar *, uschar **, uschar **);
extern int     acl_eval(int, uschar *, uschar **, uschar **);

extern tree_node *acl_var_create(uschar *);
extern void    acl_var_write(uschar *, uschar *, void *);

#ifdef EXPERIMENTAL_ARC
extern void   *arc_ams_setup_sign_bodyhash(void);
extern const uschar *arc_header_feed(gstring *, BOOL);
extern gstring *arc_sign(const uschar *, gstring *, uschar **);
extern void     arc_sign_init(void);
extern const uschar *acl_verify_arc(void);
extern uschar * fn_arc_domains(void);
#endif

extern void    assert_no_variables(void *, int, const char *, int);
extern int     auth_call_pam(const uschar *, uschar **);
extern int     auth_call_pwcheck(uschar *, uschar **);
extern int     auth_call_radius(const uschar *, uschar **);
extern int     auth_call_saslauthd(const uschar *, const uschar *,
	         const uschar *, const uschar *, uschar **);
extern int     auth_check_serv_cond(auth_instance *);
extern int     auth_check_some_cond(auth_instance *, uschar *, uschar *, int);


extern int     auth_get_data(uschar **, uschar *, int);
extern int     auth_get_no64_data(uschar **, uschar *);
extern void    auth_show_supported(FILE *);
extern uschar *auth_xtextencode(uschar *, int);
extern int     auth_xtextdecode(uschar *, uschar **);

#ifdef EXPERIMENTAL_ARC
extern gstring *authres_arc(gstring *);
#endif
#ifndef DISABLE_DKIM
extern gstring *authres_dkim(gstring *);
#endif
#ifdef EXPERIMENTAL_DMARC
extern gstring *authres_dmarc(gstring *);
#endif
extern gstring *authres_smtpauth(gstring *);
#ifdef SUPPORT_SPF
extern gstring *authres_spf(gstring *);
#endif

extern uschar *b64encode(uschar *, int);
extern int     b64decode(const uschar *, uschar **);
extern int     bdat_getc(unsigned);
extern uschar *bdat_getbuf(unsigned *);
extern int     bdat_ungetc(int);
extern void    bdat_flush_data(void);

extern void    bits_clear(unsigned int *, size_t, int *);
extern void    bits_set(unsigned int *, size_t, int *);

extern void    cancel_cutthrough_connection(BOOL, const uschar *);
extern int     check_host(void *, const uschar *, const uschar **, uschar **);
extern uschar **child_exec_exim(int, BOOL, int *, BOOL, int, ...);
extern pid_t   child_open_uid(const uschar **, const uschar **, int,
		 uid_t *, gid_t *, int *, int *, uschar *, BOOL);
extern BOOL    cleanup_environment(void);
extern void    cutthrough_data_puts(uschar *, int);
extern void    cutthrough_data_put_nl(void);
extern uschar *cutthrough_finaldot(void);
extern BOOL    cutthrough_flush_send(void);
extern BOOL    cutthrough_headers_send(void);
extern BOOL    cutthrough_predata(void);
extern void    release_cutthrough_connection(const uschar *);

extern void    daemon_go(void);

#ifdef EXPERIMENTAL_DCC
extern int     dcc_process(uschar **);
#endif

extern void    debug_logging_activate(uschar *, uschar *);
extern void    debug_logging_stop(void);
extern void    debug_print_argv(const uschar **);
extern void    debug_print_ids(uschar *);
extern void    debug_printf_indent(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    debug_print_string(uschar *);
extern void    debug_print_tree(tree_node *);
extern void    debug_vprintf(int, const char *, va_list);
extern void    decode_bits(unsigned int *, size_t, int *,
	           uschar *, bit_table *, int, uschar *, int);
extern address_item *deliver_make_addr(uschar *, BOOL);
extern void    deliver_init(void);
extern void    delivery_log(int, address_item *, int, uschar *);
extern int     deliver_message(uschar *, BOOL, BOOL);
extern void    deliver_msglog(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    deliver_set_expansions(address_item *);
extern int     deliver_split_address(address_item *);
extern void    deliver_succeeded(address_item *);

extern uschar *deliver_get_sender_address (uschar *id);
extern void    delivery_re_exec(int);

extern BOOL    directory_make(const uschar *, const uschar *, int, BOOL);
#ifndef DISABLE_DKIM
extern uschar *dkim_exim_query_dns_txt(uschar *);
extern void    dkim_exim_sign_init(void);

extern BOOL    dkim_transport_write_message(transport_ctx *,
		  struct ob_dkim *, const uschar ** errstr);
#endif
extern dns_address *dns_address_from_rr(dns_answer *, dns_record *);
extern int     dns_basic_lookup(dns_answer *, const uschar *, int);
extern void    dns_build_reverse(const uschar *, uschar *);
extern void    dns_init(BOOL, BOOL, BOOL);
extern BOOL    dns_is_aa(const dns_answer *);
extern BOOL    dns_is_secure(const dns_answer *);
extern int     dns_lookup(dns_answer *, const uschar *, int, const uschar **);
extern void    dns_pattern_init(void);
extern int     dns_special_lookup(dns_answer *, const uschar *, int, const uschar **);
extern dns_record *dns_next_rr(const dns_answer *, dns_scan *, int);
extern uschar *dns_text_type(int);
extern void    dscp_list_to_stream(FILE *);
extern BOOL    dscp_lookup(const uschar *, int, int *, int *, int *);

extern void    enq_end(uschar *);
extern BOOL    enq_start(uschar *, unsigned);
#ifndef DISABLE_EVENT
extern uschar *event_raise(uschar *, const uschar *, uschar *);
extern void    msg_event_raise(const uschar *, const address_item *);
#endif
extern const uschar * exim_errstr(int);
extern void    exim_exit(int, const uschar *);
extern void    exim_nullstd(void);
extern void    exim_setugid(uid_t, gid_t, BOOL, uschar *);
extern void    exim_wait_tick(struct timeval *, int);
extern int     exp_bool(address_item *addr,
  uschar *mtype, uschar *mname, unsigned dgb_opt, uschar *oname, BOOL bvalue,
  uschar *svalue, BOOL *rvalue);
extern BOOL    expand_check_condition(uschar *, uschar *, uschar *);
extern uschar *expand_file_big_buffer(const uschar *);
extern uschar *expand_string(uschar *);	/* public, cannot make const */
extern const uschar *expand_cstring(const uschar *); /* ... so use this one */
extern uschar *expand_hide_passwords(uschar * );
extern uschar *expand_string_copy(const uschar *);
extern int_eximarith_t expand_string_integer(uschar *, BOOL);
extern void    modify_variable(uschar *, void *);

extern BOOL    fd_ready(int, int);

extern int     filter_interpret(uschar *, int, address_item **, uschar **);
extern BOOL    filter_personal(string_item *, BOOL);
extern BOOL    filter_runtest(int, uschar *, BOOL, BOOL);
extern BOOL    filter_system_interpret(address_item **, uschar **);

extern uschar * fn_hdrs_added(void);

extern void    gstring_reset_unused(gstring *);

extern void    header_add(int, const char *, ...);
extern int     header_checkname(header_line *, BOOL);
extern BOOL    header_match(uschar *, BOOL, BOOL, string_item *, int, ...);
extern int     host_address_extract_port(uschar *);
extern uschar *host_and_ident(BOOL);
extern int     host_aton(const uschar *, int *);
extern void    host_build_hostlist(host_item **, const uschar *, BOOL);
extern ip_address_item *host_build_ifacelist(const uschar *, uschar *);
extern void    host_build_log_info(void);
extern void    host_build_sender_fullhost(void);
extern int     host_find_byname(host_item *, const uschar *, int,
				const uschar **, BOOL);
extern int     host_find_bydns(host_item *, const uschar *, int, uschar *, uschar *,
                 uschar *, const dnssec_domains *, const uschar **, BOOL *);
extern ip_address_item *host_find_interfaces(void);
extern BOOL    host_is_in_net(const uschar *, const uschar *, int);
extern BOOL    host_is_tls_on_connect_port(int);
extern int     host_item_get_port(host_item *);
extern void    host_mask(int, int *, int);
extern int     host_name_lookup(void);
extern int     host_nmtoa(int, int *, int, uschar *, int);
extern uschar *host_ntoa(int, const void *, uschar *, int *);
extern int     host_scan_for_local_hosts(host_item *, host_item **, BOOL *);

extern uschar *imap_utf7_encode(uschar *, const uschar *,
				 uschar, uschar *, uschar **);

extern void    invert_address(uschar *, uschar *);
extern int     ip_addr(void *, int, const uschar *, int);
extern int     ip_bind(int, int, uschar *, int);
extern int     ip_connect(int, int, const uschar *, int, int, const blob *);
extern int     ip_connectedsocket(int, const uschar *, int, int,
                 int, host_item *, uschar **, const blob *);
extern int     ip_get_address_family(int);
extern void    ip_keepalive(int, const uschar *, BOOL);
extern int     ip_recv(client_conn_ctx *, uschar *, int, int);
extern int     ip_socket(int, int);

extern int     ip_tcpsocket(const uschar *, uschar **, int);
extern int     ip_unixsocket(const uschar *, uschar **);
extern int     ip_streamsocket(const uschar *, uschar **, int);

extern int     ipv6_nmtoa(int *, uschar *);

extern uschar *local_part_quote(uschar *);
extern int     log_create(uschar *);
extern int     log_create_as_exim(uschar *);
extern void    log_close_all(void);

extern macro_item * macro_create(const uschar *, const uschar *, BOOL);
extern BOOL    macro_read_assignment(uschar *);
extern uschar *macros_expand(int, int *, BOOL *);
extern void    mainlog_close(void);
#ifdef WITH_CONTENT_SCAN
extern int     malware(const uschar *, int);
extern int     malware_in_file(uschar *);
extern void    malware_init(void);
extern void    malware_show_supported(FILE *);
#endif
extern int     match_address_list(const uschar *, BOOL, BOOL, const uschar **,
                 unsigned int *, int, int, const uschar **);
extern int     match_address_list_basic(const uschar *, const uschar **, int);
extern int     match_check_list(const uschar **, int, tree_node **, unsigned int **,
                 int(*)(void *, const uschar *, const uschar **, uschar **), void *, int,
                 const uschar *, const uschar **);
extern int     match_isinlist(const uschar *, const uschar **, int, tree_node **,
                 unsigned int *, int, BOOL, const uschar **);
extern int     match_check_string(const uschar *, const uschar *, int, BOOL, BOOL, BOOL,
                 const uschar **);
extern void    md5_end(md5 *, const uschar *, int, uschar *);
extern void    md5_mid(md5 *, const uschar *);
extern void    md5_start(md5 *);
extern void    millisleep(int);
#ifdef WITH_CONTENT_SCAN
struct mime_boundary_context;
extern int     mime_acl_check(uschar *acl, FILE *f,
                 struct mime_boundary_context *, uschar **, uschar **);
extern int     mime_decode(const uschar **);
extern ssize_t mime_decode_base64(FILE *, FILE *, uschar *);
extern int     mime_regex(const uschar **);
extern void    mime_set_anomaly(int);
#endif
extern uschar *moan_check_errorcopy(uschar *);
extern BOOL    moan_skipped_syntax_errors(uschar *, error_block *, uschar *,
                 BOOL, uschar *);
extern void    moan_smtp_batch(uschar *, const char *, ...) PRINTF_FUNCTION(2,3);
extern BOOL    moan_send_message(uschar *, int, error_block *eblock,
		 header_line *, FILE *, uschar *);
extern void    moan_tell_someone(uschar *, address_item *,
                 const uschar *, const char *, ...) PRINTF_FUNCTION(4,5);
extern BOOL    moan_to_sender(int, error_block *, header_line *, FILE *, BOOL);
extern void    moan_write_from(FILE *);
extern FILE   *modefopen(const uschar *, const char *, mode_t);

extern int     open_cutthrough_connection( address_item * addr );

extern uschar *parse_extract_address(uschar *, uschar **, int *, int *, int *,
                 BOOL);
extern int     parse_forward_list(uschar *, int, address_item **, uschar **,
                 const uschar *, uschar *, error_block **);
extern uschar *parse_find_address_end(uschar *, BOOL);
extern uschar *parse_find_at(uschar *);
extern const uschar *parse_fix_phrase(const uschar *, int, uschar *, int);
extern uschar *parse_message_id(uschar *, uschar **, uschar **);
extern const uschar *parse_quote_2047(const uschar *, int, uschar *, uschar *, int, BOOL);
extern uschar *parse_date_time(uschar *str, time_t *t);
extern int     vaguely_random_number(int);
#ifdef SUPPORT_TLS
extern int     vaguely_random_number_fallback(int);
#endif

extern BOOL    queue_action(uschar *, int, uschar **, int, int);
extern void    queue_check_only(void);
extern void    queue_list(int, uschar **, int);
extern void    queue_count(void);
extern void    queue_run(uschar *, uschar *, BOOL);

extern int     random_number(int);
extern int     rda_interpret(redirect_block *, int, uschar *, uschar *,
                 uschar *, uschar *, uschar *, ugid_block *, address_item **,
                 uschar **, error_block **, int *, uschar *);
extern int     rda_is_filter(const uschar *);
extern BOOL    readconf_depends(driver_instance *, uschar *);
extern void    readconf_driver_init(uschar *, driver_instance **,
                 driver_info *, int, void *, int, optionlist *, int);
extern uschar *readconf_find_option(void *);
extern void    readconf_main(BOOL);
extern void    readconf_options_from_list(optionlist *, unsigned, const uschar *, uschar *);
extern BOOL    readconf_print(uschar *, uschar *, BOOL);
extern uschar *readconf_printtime(int);
extern uschar *readconf_readname(uschar *, int, uschar *);
extern int     readconf_readtime(const uschar *, int, BOOL);
extern void    readconf_rest(void);
extern uschar *readconf_retry_error(const uschar *, const uschar *, int *, int *);
extern void    readconf_save_config(const uschar *);
extern void    read_message_body(BOOL);
extern void    receive_bomb_out(uschar *, uschar *);
extern BOOL    receive_check_fs(int);
extern BOOL    receive_check_set_sender(uschar *);
extern BOOL    receive_msg(BOOL);
extern int_eximarith_t receive_statvfs(BOOL, int *);
extern void    receive_swallow_smtp(void);
#ifdef WITH_CONTENT_SCAN
extern int     regex(const uschar **);
#endif
extern BOOL    regex_match_and_setup(const pcre *, const uschar *, int, int);
extern const pcre *regex_must_compile(const uschar *, BOOL, BOOL);
extern void    retry_add_item(address_item *, uschar *, int);
extern BOOL    retry_check_address(const uschar *, host_item *, uschar *, BOOL,
                 uschar **, uschar **);
extern retry_config *retry_find_config(const uschar *, const uschar *, int, int);
extern BOOL    retry_ultimate_address_timeout(uschar *, const uschar *,
                 dbdata_retry *, time_t);
extern void    retry_update(address_item **, address_item **, address_item **);
extern uschar *rewrite_address(uschar *, BOOL, BOOL, rewrite_rule *, int);
extern uschar *rewrite_address_qualify(uschar *, BOOL);
extern header_line *rewrite_header(header_line *,
               const uschar *, const uschar *,
               rewrite_rule *, int, BOOL);
extern uschar *rewrite_one(uschar *, int, BOOL *, BOOL, uschar *,
                 rewrite_rule *);
extern void    rewrite_test(uschar *);
extern uschar *rfc2047_decode2(uschar *, BOOL, uschar *, int, int *, int *,
                 uschar **);
extern int     route_address(address_item *, address_item **, address_item **,
                 address_item **, address_item **, int);
extern int     route_check_prefix(const uschar *, const uschar *);
extern int     route_check_suffix(const uschar *, const uschar *);
extern BOOL    route_findgroup(uschar *, gid_t *);
extern BOOL    route_finduser(const uschar *, struct passwd **, uid_t *);
extern BOOL    route_find_expanded_group(uschar *, uschar *, uschar *, gid_t *,
                 uschar **);
extern BOOL    route_find_expanded_user(uschar *, uschar *, uschar *,
                 struct passwd **, uid_t *, uschar **);
extern void    route_init(void);
extern void    route_show_supported(FILE *);
extern void    route_tidyup(void);

extern uschar *search_find(void *, uschar *, uschar *, int, const uschar *, int,
                 int, int *);
extern int     search_findtype(const uschar *, int);
extern int     search_findtype_partial(const uschar *, int *, const uschar **, int *,
                 int *);
extern void   *search_open(uschar *, int, int, uid_t *, gid_t *);
extern void    search_tidyup(void);
extern void    set_process_info(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    sha1_end(hctx *, const uschar *, int, uschar *);
extern void    sha1_mid(hctx *, const uschar *);
extern void    sha1_start(hctx *);
extern int     sieve_interpret(uschar *, int, uschar *, uschar *, uschar *,
                 uschar *, address_item **, uschar **);
extern void    sigalrm_handler(int);
extern BOOL    smtp_buffered(void);
extern void    smtp_closedown(uschar *);
extern void    smtp_command_timeout_exit(void);
extern void    smtp_command_sigterm_exit(void);
extern void    smtp_data_timeout_exit(void);
extern void    smtp_data_sigint_exit(void);
extern uschar *smtp_cmd_hist(void);
extern int     smtp_connect(smtp_connect_args *, const blob *);
extern int     smtp_sock_connect(host_item *, int, int, uschar *,
		 transport_instance * tb, int, const blob *);
extern int     smtp_feof(void);
extern int     smtp_ferror(void);
extern uschar *smtp_get_connection_info(void);
extern BOOL    smtp_get_interface(uschar *, int, address_item *,
                 uschar **, uschar *);
extern BOOL    smtp_get_port(uschar *, address_item *, int *, uschar *);
extern int     smtp_getc(unsigned);
extern uschar *smtp_getbuf(unsigned *);
extern void    smtp_get_cache(void);
extern int     smtp_handle_acl_fail(int, int, uschar *, uschar *);
extern void    smtp_log_no_mail(void);
extern void    smtp_message_code(uschar **, int *, uschar **, uschar **, BOOL);
extern void    smtp_proxy_tls(void *, uschar *, size_t, int *, int);
extern BOOL    smtp_read_response(void *, uschar *, int, int, int);
extern void    smtp_reset(void *);
extern void    smtp_respond(uschar *, int, BOOL, uschar *);
extern void    smtp_notquit_exit(uschar *, uschar *, uschar *, ...);
extern void    smtp_port_for_connect(host_item *, int);
extern void    smtp_send_prohibition_message(int, uschar *);
extern int     smtp_setup_msg(void);
extern BOOL    smtp_start_session(void);
extern int     smtp_ungetc(int);
extern BOOL    smtp_verify_helo(void);
extern int     smtp_write_command(void *, int, const char *, ...) PRINTF_FUNCTION(3,4);
#ifdef WITH_CONTENT_SCAN
extern int     spam(const uschar **);
extern FILE   *spool_mbox(unsigned long *, const uschar *, uschar **);
#endif
extern void    spool_clear_header_globals(void);
extern uschar *spool_dname(const uschar *, uschar *);
extern uschar *spool_fname(const uschar *, const uschar *, const uschar *, const uschar *);
extern BOOL    spool_move_message(uschar *, uschar *, uschar *, uschar *);
extern int     spool_open_datafile(uschar *);
extern int     spool_open_temp(uschar *);
extern int     spool_read_header(uschar *, BOOL, BOOL);
extern uschar *spool_sname(const uschar *, uschar *);
extern int     spool_write_header(uschar *, int, uschar **);
extern int     stdin_getc(unsigned);
extern int     stdin_feof(void);
extern int     stdin_ferror(void);
extern int     stdin_ungetc(int);
extern gstring *string_append(gstring *, int, ...) WARN_UNUSED_RESULT;
extern gstring *string_append_listele(gstring *, uschar, const uschar *) WARN_UNUSED_RESULT;
extern gstring *string_append_listele_n(gstring *, uschar, const uschar *, unsigned) WARN_UNUSED_RESULT;
extern gstring *string_append2_listele_n(gstring *, const uschar *, const uschar *, unsigned) WARN_UNUSED_RESULT;
extern uschar *string_base62(unsigned long int);
extern gstring *string_cat (gstring *, const uschar *     ) WARN_UNUSED_RESULT;
extern gstring *string_catn(gstring *, const uschar *, int) WARN_UNUSED_RESULT;
extern int     string_compare_by_pointer(const void *, const void *);
extern uschar *string_copy_dnsdomain(uschar *);
extern uschar *string_copy_malloc(const uschar *);
extern uschar *string_copylc(const uschar *);
extern uschar *string_copynlc(uschar *, int);
extern uschar *string_dequote(const uschar **);
extern gstring *string_fmt_append(gstring *, const char *, ...) ALMOST_PRINTF(2,3);
extern BOOL    string_format(uschar *, int, const char *, ...) ALMOST_PRINTF(3,4);
extern uschar *string_format_size(int, uschar *);
extern uschar *string_from_gstring(gstring *);
extern gstring *string_get(unsigned);
extern int     string_interpret_escape(const uschar **);
extern int     string_is_ip_address(const uschar *, int *);
#ifdef SUPPORT_I18N
extern BOOL    string_is_utf8(const uschar *);
#endif
extern uschar *string_nextinlist(const uschar **, int *, uschar *, int);
extern uschar *string_open_failed(int, const char *, ...) PRINTF_FUNCTION(2,3);
extern const uschar *string_printing2(const uschar *, BOOL);
extern uschar *string_split_message(uschar *);
extern uschar *string_timediff(struct timeval *);
extern uschar *string_timesince(struct timeval *);
extern uschar *string_unprinting(uschar *);
#ifdef SUPPORT_I18N
extern uschar *string_address_utf8_to_alabel(const uschar *, uschar **);
extern uschar *string_domain_alabel_to_utf8(const uschar *, uschar **);
extern uschar *string_domain_utf8_to_alabel(const uschar *, uschar **);
extern uschar *string_localpart_alabel_to_utf8(const uschar *, uschar **);
extern uschar *string_localpart_utf8_to_alabel(const uschar *, uschar **);
#endif
extern gstring *string_vformat(gstring *, BOOL, const char *, va_list);
extern int     strcmpic(const uschar *, const uschar *);
extern int     strncmpic(const uschar *, const uschar *, int);
extern uschar *strstric(uschar *, uschar *, BOOL);

#ifdef EXIM_TFO_PROBE
extern void    tfo_probe(void);
#endif
extern void    timesince(struct timeval * diff, struct timeval * then);
extern void    tls_modify_variables(tls_support *);
extern uschar *tod_stamp(int);

extern BOOL    transport_check_waiting(const uschar *, const uschar *, int, uschar *,
                 BOOL *, oicf, void*);
extern void    transport_init(void);
extern void    transport_do_pass_socket(const uschar *, const uschar *,
		 const uschar *, uschar *, int);
extern BOOL    transport_pass_socket(const uschar *, const uschar *, const uschar *, uschar *,
                 int);
extern uschar *transport_rcpt_address(address_item *, BOOL);
extern BOOL    transport_set_up_command(const uschar ***, uschar *,
		 BOOL, int, address_item *, uschar *, uschar **);
extern void    transport_update_waiting(host_item *, uschar *);
extern BOOL    transport_write_block(transport_ctx *, uschar *, int, BOOL);
extern void    transport_write_reset(int);
extern BOOL    transport_write_string(int, const char *, ...);
extern BOOL    transport_headers_send(transport_ctx *,
                 BOOL (*)(transport_ctx *, uschar *, int));
extern void    transport_show_supported(FILE *);
extern BOOL    transport_write_message(transport_ctx *, int);
extern void    tree_add_duplicate(uschar *, address_item *);
extern void    tree_add_nonrecipient(uschar *);
extern void    tree_add_unusable(host_item *);
extern int     tree_insertnode(tree_node **, tree_node *);
extern tree_node *tree_search(tree_node *, const uschar *);
extern void    tree_write(tree_node *, FILE *);
extern void    tree_walk(tree_node *, void (*)(uschar*, uschar*, void*), void *);

#ifdef WITH_CONTENT_SCAN
extern void    unspool_mbox(void);
#endif
#ifdef SUPPORT_I18N
extern void    utf8_version_report(FILE *);
#endif

extern int     verify_address(address_item *, FILE *, int, int, int, int,
                 uschar *, uschar *, BOOL *);
extern int     verify_check_dnsbl(int, const uschar **, uschar **);
extern int     verify_check_header_address(uschar **, uschar **, int, int, int,
                 uschar *, uschar *, int, int *);
extern int     verify_check_headers(uschar **);
extern int     verify_check_header_names_ascii(uschar **);
extern int     verify_check_host(uschar **);
extern int     verify_check_notblind(void);
extern int     verify_check_given_host(const uschar **, const host_item *);
extern int     verify_check_this_host(const uschar **, unsigned int *,
	         const uschar*, const uschar *, const uschar **);
extern address_item *verify_checked_sender(uschar *);
extern void    verify_get_ident(int);
extern BOOL    verify_sender(int *, uschar **);
extern BOOL    verify_sender_preliminary(int *, uschar **);
extern void    version_init(void);

extern BOOL    write_chunk(transport_ctx *, uschar *, int);
extern ssize_t write_to_fd_buf(int, const uschar *, size_t);


/* vi: aw
*/
/* End of functions.h */
