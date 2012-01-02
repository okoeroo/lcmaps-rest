#include <syslog.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_openssl.h>

#include "common_callbacks.h"
#include "lcmapsd_fullssl.h"


int
main(int argc, char ** argv) {
    evbase_t * evbase = event_base_new();
    evhtp_t  * htp    = evhtp_new(evbase, NULL);
    evhtp_ssl_cfg_t scfg = {
            .pemfile            = "/Users/okoeroo/dvl/certs/ca/test_localhost_with_subjectAltName/hostcert.pem",
            .privfile           = "/Users/okoeroo/dvl/certs/ca/test_localhost_with_subjectAltName/hostkey.pem",
            .cafile             = NULL,
            .capath             = "/etc/grid-security/certificates/",
            .ciphers            = "ALL:!ADH:!LOW:!EXP:@STRENGTH",
            .ssl_opts           = SSL_OP_NO_SSLv2,
            .verify_peer        = SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_PEER,
            .verify_depth       = 42,
            /* .x509_verify_cb     = dummy_ssl_verify_callback, */
            /* .x509_chk_issued_cb = dummy_check_issued_cb, */
            .x509_verify_cb     = NULL,
            .x509_chk_issued_cb = NULL,
            .scache_type        = evhtp_ssl_scache_type_internal,
            .scache_size        = 1024,
            .scache_timeout     = 1024,
            .scache_init        = NULL,
            .scache_add         = NULL,
            .scache_get         = NULL,
            .scache_del         = NULL,
    };

#if 0
    void * lcmaps_handle = dlopen("liblcmaps.dylib");
    if (!lcmaps_handle) {
        printf ("handle not found, gtfo\n");
    } else {
        printf ("handle found!\n");
    }
#endif

    openlog("lcmapsd", LOG_NDELAY|LOG_PID, LOG_LOCAL2);

    evhtp_ssl_init(htp, &scfg);

    srand((unsigned)time(NULL));

    /* evhtp_set_post_accept_cb(htp, my_accept_cb, NULL); */

    lcmapsd_fullssl_init(htp); /* register callbacks and such */
    evhtp_bind_socket(htp, "0.0.0.0", 8008, 1024);
    event_base_loop(evbase, 0);

    closelog();

    return 0;
}

