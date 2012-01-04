#include <syslog.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_openssl.h>

#include "lcmapsd_common.h"
#include "lcmapsd_httprest.h"
#include "lcmapsd_fullssl.h"


int
main(int argc, char ** argv) {
    evbase_t * evbase = event_base_new();

    openlog("lcmapsd", LOG_NDELAY|LOG_PID, LOG_LOCAL2);
    srand((unsigned)time(NULL));

#if 0
    void * lcmaps_handle = dlopen("liblcmaps.dylib");
    if (!lcmaps_handle) {
        printf ("handle not found, gtfo\n");
    } else {
        printf ("handle found!\n");
    }
#endif
    /* evhtp_set_post_accept_cb(htp, my_accept_cb, NULL); */

    /* register callbacks and such */

    lcmapsd_fullssl_init(evbase);
    lcmapsd_httprest_init(evbase);
    event_base_loop(evbase, 0);

    closelog();

    return 0;
}

