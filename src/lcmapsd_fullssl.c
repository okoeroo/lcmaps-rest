#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_openssl.h>
#include "lcmapsd_common.h"
#include "lcmapsd_fullssl.h"

#include <openssl/x509v3.h>

#define LCMAPSD_FULLSSL_URI         "/lcmaps/mapping/ssl"
#define LCMAPSD_FULLSSL_BIND_IP     "0.0.0.0"
#define LCMAPSD_FULLSSL_BIND_PORT   8443
#define LCMAPSD_FULLSSL_LISTENERS   1024


static int lcmapsd_push_peer_certificate_to_chain(STACK_OF(X509) * chain, X509 * cert);
static evhtp_res lcmapsd_perform_lcmaps(evhtp_request_t *, STACK_OF(X509) *);
static void lcmapsd_fullssl_cb(evhtp_request_t *, void *);

static int lcmapsd_push_peer_certificate_to_chain(STACK_OF(X509) * chain, X509 * cert) {
    return sk_X509_insert(chain, cert, 0);;
}

static evhtp_res
lcmapsd_perform_lcmaps(evhtp_request_t * req, STACK_OF(X509) * chain) {
    evhtp_res        resp_code   = 0;
    uid_t            uid         = -1;
    gid_t *          pgid_list   = NULL;
    int              npgid       = 0;
    gid_t *          sgid_list   = NULL;
    int              nsgid       = 0;
    char *           poolindexp  = NULL;
    int              lcmaps_res  = 0;

    /* No chain, no game */
    if (!chain) {
        resp_code = EVHTP_RES_UNAUTH; /* 401 */
        goto end;
    }

    /* Go to LCMAPS */
    if (lcmaps_init(NULL) != 0) {
        /* Unable to initialize LCMAPS, have a look at the config file and
         * logfile */
        resp_code = EVHTP_RES_SERVUNAVAIL; /* 503 */
        goto end;
    }

    lcmaps_res = lcmaps_run_with_stack_of_x509_and_return_account(
                chain,
                -1,
                NULL,
                0,
                NULL,
                &uid,
                &pgid_list,
                &npgid,
                &sgid_list,
                &nsgid,
                &poolindexp);
    if (lcmaps_res != 0) {
        resp_code = EVHTP_RES_FORBIDDEN; /* 403 */
        goto end;
    }
    if (lcmaps_term() != 0) {
        /* Could not tierdown LCMAPS */
        resp_code = EVHTP_RES_SERVERR; /* 500 */
        goto end;
    }

    /* Construct message body */
    switch (lcmapsd_select_return_format(req)) {
        case TYPE_JSON:
            lcmapsd_construct_mapping_in_json(req->buffer_out,
                                              uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
            evhtp_headers_add_header(req->headers_out,
                                     evhtp_header_new("Content-Type", "application/json", 0, 0));
            break;
        case TYPE_XML:
            lcmapsd_construct_mapping_in_xml(req->buffer_out,
                                             uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
            evhtp_headers_add_header(req->headers_out,
                                     evhtp_header_new("Content-Type", "text/xml", 0, 0));
            break;
        case TYPE_HTML:
            lcmapsd_construct_mapping_in_html(req->buffer_out,
                                              uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
            evhtp_headers_add_header(req->headers_out,
                                     evhtp_header_new("Content-Type", "text/html", 0, 0));
            break;
        default:
            /* Fail, unsupported format */
            lcmapsd_construct_error_reply_in_html(req->buffer_out,
                                                  "Wrong format query or accept header value",
                                                  "The value in the format query or accept header value " \
                                                  "is not supported.<br>\n" \
                                                  "In the ?format=<value> use the values: \"json\", \"xml\" " \
                                                  "or \"html\", or leave the entire query out.<br>\n"
                                                  "Or trust on the \"accept:\" HTTP headers to be set.<br>\n" \
                                                  "Use \"application/json\", \"text/xml\", \"text/html\" or \"*/*\".");
            resp_code = EVHTP_RES_BADREQ; /* 400 */
            goto end;
    }
    resp_code = EVHTP_RES_OK; /* 200 */

end:
    free(pgid_list);
    free(sgid_list);

    return resp_code;
}

static void
lcmapsd_fullssl_cb(evhtp_request_t * req, void * a) {
    STACK_OF (X509) *px509_chain = NULL;
    X509            *px509       = NULL;
    evhtp_res        lcmaps_res  = 0;

#ifdef DEBUG
    printf("lcmapsd_fullssl_cb on the URI: \"" LCMAPSD_FULLSSL_URI "\"\n");
#endif
    if (!req) {
        syslog(LOG_ERR, "No request object! - problem in evhtp/libevent\n");
        return;
    }
    if (!req->conn) {
        syslog(LOG_ERR, "No connection object in request object - problem in evhtp/libevent\n");
        return;
    }
    if (!req->conn->ssl) {
        syslog(LOG_ERR, "No SSL object connection object - required for this URI\n");
        lcmapsd_construct_error_reply_in_html(req->buffer_out,
                                              "No SSL initiated",
                                              "The URI \"%s\" hosted on port %d is exclusively SSL.",
                                              LCMAPSD_FULLSSL_URI,
                                              LCMAPSD_FULLSSL_BIND_PORT);
        evhtp_send_reply(req, EVHTP_RES_METHNALLOWED); /* 405 */
        return;
    }

#ifdef DEBUG
    printf("Got SSL enabled link\n");
#endif
    /* BUG: Still connected after SSL failed.
            Example: wrong certificate purpose on the server side (using a
            client cert) AND when the host cert is expired (might be a
            feature :). */
    /* BUG: When the SSL_VERIFY_FAIL_IF_NO_PEER_CERT is enforced, I still
            get here. Clients see: curl: (35) error:14094410:SSL
            routines:SSL3_READ_BYTES:sslv3 alert handshake failure */
            /* Fix offered: https://github.com/ellzey/libevhtp/pull/29 */

    /* Need to have hostname to potentially compare dnsAltNames of the
     * peer's certificate when auth'ed from a machine */


    /* Get only the peer certificate, not the chain */
    px509 = SSL_get_peer_certificate(req->conn->ssl);
    if (!px509) {
        printf("No peer certificate. Full SSL is impossible\n");
        lcmapsd_construct_error_reply_in_html(req->buffer_out,
                                              "No peer certificate provided",
                                              "The URI \"%s\" hosted on port %d is exclusively SSL" \
                                              "and requires a peer certificate (chain) to be provided.",
                                              LCMAPSD_FULLSSL_URI,
                                              LCMAPSD_FULLSSL_BIND_PORT);
        evhtp_send_reply(req, EVHTP_RES_UNAUTH); /* 401 */
        return;
    }

    /* Get certificate chain */
    px509_chain = SSL_get_peer_cert_chain(req->conn->ssl);

    if (!px509_chain) {
        /* Create a certificate chain */
        px509_chain = sk_X509_new(px509); /* Needs clean up! */
    } else {
        /* Add the peer certificate to the chain, because I want a complete chain */
        lcmapsd_push_peer_certificate_to_chain(px509_chain, px509);
    }

#ifdef DEBUG
    /* And again */
    int i = 0;

    if (!px509_chain) {
        printf("No peer cert chain\n");
    } else {
        /* Push certificates in chain into the BIO memory stack */
        for (i = 0; i < sk_X509_num(px509_chain); i++)  {
            px509 = sk_X509_value(px509_chain, i);
            if (px509) {
                X509_NAME_oneline(X509_get_subject_name(px509), tmp_dn, 256);
                printf("Depth level %i: Subject DN: %s\n", i, tmp_dn);
            }
        }
    }
#endif /* DEBUG */

    lcmaps_res = lcmapsd_perform_lcmaps(req, px509_chain);
    evhtp_send_reply(req, lcmaps_res);
    return;
}

int
lcmapsd_fullssl_init(evbase_t * evbase) {
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
            .x509_verify_cb     = scas_verify_callback,
            .x509_chk_issued_cb = grid_check_issued_wrapper,
            .scache_type        = evhtp_ssl_scache_type_internal,
            .scache_size        = 1024,
            .scache_timeout     = 1024,
            .scache_init        = NULL,
            .scache_add         = NULL,
            .scache_get         = NULL,
            .scache_del         = NULL,
    };

    evhtp_ssl_init(htp, &scfg);

#if OPENSSL_VERSION_NUMBER < 0x00908000L
    X509_STORE_set_flags(SSL_CTX_get_cert_store(htp->ssl_ctx), X509_V_FLAG_CRL_CHECK |
            X509_V_FLAG_CRL_CHECK_ALL );
#else
    X509_STORE_set_flags(SSL_CTX_get_cert_store(htp->ssl_ctx), X509_V_FLAG_CRL_CHECK |
            X509_V_FLAG_CRL_CHECK_ALL |
            X509_V_FLAG_ALLOW_PROXY_CERTS );
#endif /* OPENSSL_VERSION_NUMBER < 0x00908000L */

    evhtp_set_cb(htp, LCMAPSD_FULLSSL_URI, lcmapsd_fullssl_cb, NULL);
    evhtp_bind_socket(htp, LCMAPSD_FULLSSL_BIND_IP, LCMAPSD_FULLSSL_BIND_PORT, LCMAPSD_FULLSSL_LISTENERS);

    return 0;
}

