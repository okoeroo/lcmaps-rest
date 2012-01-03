#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_basic.h>


#ifndef LCMAPSD_HTTPREST_H
    #define LCMAPSD_HTTPREST_H

int lcmapsd_httprest_init(evbase_t *);

#endif /* LCMAPSD_HTTPREST_H */
