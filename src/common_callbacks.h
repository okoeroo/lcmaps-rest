#include <syslog.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>


#ifndef COMMON_CALLBACKS_H
#define COMMON_CALLBACKS_H


int dummy_ssl_verify_callback(int ok, X509_STORE_CTX * x509_store);
int dummy_check_issued_cb(X509_STORE_CTX * ctx, X509 * x, X509 * issuer);
evhtp_res my_accept_cb(evhtp_connection_t * conn, void * arg);


#endif /* COMMON_CALLBACKS_H */
