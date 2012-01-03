#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_openssl.h>


#ifndef LCMAPSD_FULLSSL_H
    #define LCMAPSD_FULLSSL_H

int lcmapsd_fullssl_init(evbase_t *);

#endif /* LCMAPSD_FULLSSL_H */
