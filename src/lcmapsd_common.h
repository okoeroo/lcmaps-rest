#include <syslog.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <evhtp.h>

#include "lcmapsd.h"

#ifndef LCMAPSD_COMMON_H
#define LCMAPSD_COMMON_H

#define TYPE_UNKNOWN    0
#define TYPE_JSON       1
#define TYPE_XML        2
#define TYPE_HTML       3

int lcmapsd_select_return_format(evhtp_request_t *req);
int dummy_ssl_verify_callback(int ok, X509_STORE_CTX * x509_store);
int dummy_check_issued_cb(X509_STORE_CTX * ctx, X509 * x, X509 * issuer);
evhtp_res my_accept_cb(evhtp_connection_t * conn, void * arg);

int
lcmapsd_construct_error_reply_in_html(struct evbuffer *buf,
                                      const char * title,
                                      const char * body_fmt,
                                      ...);
int
lcmapsd_construct_mapping_in_html(struct evbuffer *buf,
                                  uid_t            uid,
                                  gid_t *          pgid_list,
                                  int              npgid,
                                  gid_t *          sgid_list,
                                  int              nsgid,
                                  char *           poolindex);
int
lcmapsd_construct_mapping_in_xml(struct evbuffer *buf,
                                  uid_t            uid,
                                  gid_t *          pgid_list,
                                  int              npgid,
                                  gid_t *          sgid_list,
                                  int              nsgid,
                                  char *           poolindex);
int
lcmapsd_construct_mapping_in_json(struct evbuffer *buf,
                                  uid_t            uid,
                                  gid_t *          pgid_list,
                                  int              npgid,
                                  gid_t *          sgid_list,
                                  int              nsgid,
                                  char *           poolindex);

#define PROXYCERTINFO_OID      "1.3.6.1.5.5.7.1.14"
#define OLD_PROXYCERTINFO_OID  "1.3.6.1.4.1.3536.1.222"

int grid_check_issued_wrapper(X509_STORE_CTX *ctx,X509 *x,X509 *issuer);
int scas_verify_callback(int ok, X509_STORE_CTX *store_ctx);

time_t lcmapsd_tm2time_t_in_utc(struct tm *tm);
int asn1time_to_time(ASN1_TIME *asn1time, time_t *result);
int x509IsCA (X509 *cert);

unsigned long grid_X509_knownCriticalExts(X509 *cert);
unsigned long grid_verifyProxy( STACK_OF(X509) *certstack);


#endif /* LCMAPSD_COMMON_H */
