#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#define LCMAPS_USE_DLOPEN
#include <lcmaps/lcmaps_openssl.h>


#ifndef LCMAPSD_FULLSSL_H
    #define LCMAPSD_FULLSSL_H

void lcmapsd_fullssl_cb(evhtp_request_t *, void *);
int lcmapsd_fullssl_init(evhtp_t *);
static evhtp_res lcmapsd_perform_lcmaps(evhtp_request_t *, STACK_OF(X509) *);

#endif /* LCMAPSD_FULLSSL_H */
