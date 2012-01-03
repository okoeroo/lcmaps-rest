#include <syslog.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <pwd.h>
#include <evhtp.h>

#include "lcmapsd.h"

#ifndef LCMAPSD_COMMON_H
#define LCMAPSD_COMMON_H


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

#endif /* LCMAPSD_COMMON_H */
