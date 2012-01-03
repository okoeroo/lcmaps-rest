#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_openssl.h>
#include "lcmapsd_common.h"
#include "lcmapsd_fullssl.h"


#define LCMAPSD_FULLSSL_URI         "/lcmaps/mapping/ssl"
#define LCMAPSD_FULLSSL_BIND_IP     "0.0.0.0"
#define LCMAPSD_FULLSSL_BIND_PORT   8443
#define LCMAPSD_FULLSSL_LISTENERS   1024


static int lcmapsd_push_peer_certificate_to_chain(STACK_OF(X509) * chain, X509 * cert);
static evhtp_res lcmapsd_perform_lcmaps(evhtp_request_t *, STACK_OF(X509) *);

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
    const char *     format      = NULL;

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
    format = evhtp_kv_find(req->uri->query, "format");
    if (format) {
        if (strcasecmp("json", format) == 0) {
            lcmapsd_construct_mapping_in_json(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
        } else if (strcasecmp("xml", format) == 0) {
            lcmapsd_construct_mapping_in_xml(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
        } else if (strcasecmp("html", format) == 0) {
            lcmapsd_construct_mapping_in_html(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
        } else {
            /* Fail, unsupported format */
            lcmapsd_construct_error_reply_in_html(req->buffer_out,
                                                  "Wrong format value",
                                                  "The format \"%s\" is not supported. Use json, xml or " \
                                                  "html. Leave it out of the query for the default in JSON.",
                                                  format);
            resp_code = EVHTP_RES_BADREQ; /* 400 */
            goto end;
        }
    } else {
        /* Default response in JSON */
        lcmapsd_construct_mapping_in_json(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
    }
    resp_code = EVHTP_RES_OK; /* 200 */

end:
    free(pgid_list);
    free(sgid_list);

    return resp_code;
}

void
lcmapsd_fullssl_cb(evhtp_request_t * req, void * a) {
    STACK_OF (X509) *px509_chain = NULL;
    X509            *px509       = NULL;
    evhtp_res        lcmaps_res  = 0;

    printf("lcmapsd_fullssl_cb on the URI: \"" LCMAPSD_FULLSSL_URI "\"\n");
    if (!req) {
        printf("No request object! - problem in evhtp/libevent\n");
        return;
    }
    if (!req->conn) {
        printf("No connection object in request object - problem in evhtp/libevent\n");
        return;
    }
    if (!req->conn->ssl) {
        printf("No SSL object connection object - required for this URI\n");
        evhtp_send_reply(req, EVHTP_RES_METHNALLOWED); /* 405 */
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

    evhtp_ssl_init(htp, &scfg);
    evhtp_set_cb(htp, LCMAPSD_FULLSSL_URI, lcmapsd_fullssl_cb, NULL);
    evhtp_bind_socket(htp, LCMAPSD_FULLSSL_BIND_IP, LCMAPSD_FULLSSL_BIND_PORT, LCMAPSD_FULLSSL_LISTENERS);

    return 0;
}

