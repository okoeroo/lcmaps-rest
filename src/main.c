#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

void
testcb(evhtp_request_t * req, void * a) {
    int i = 0;
    STACK_OF (X509) * px509_chain = NULL;
    X509 *            px509       = NULL;
    char              tmp_dn[256];

    printf("testcb on the URI: \"/lcmaps\"\n");
    if (req->conn->ssl) {
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
        printf("Got SSL enabled link\n");
        /* Get certificate chain */
        px509_chain = SSL_get_peer_cert_chain(req->conn->ssl);
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
        /* Get only the peer certificate, not the chain */
        px509 = SSL_get_peer_certificate(req->conn->ssl);
        if (px509) {
            X509_NAME_oneline(X509_get_subject_name(px509), tmp_dn, 256);
            printf("Subject DN: %s\n", tmp_dn); 
        }

        /* Add the peer certificate to the chain, because I want a complete chain */
        sk_X509_insert(px509_chain, px509, 0);

        /* And again */
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
    }

    evbuffer_add_reference(req->buffer_out, "foobar", 6, NULL, NULL);
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static int
dummy_ssl_verify_callback(int ok, X509_STORE_CTX * x509_store) {
    return 1;
}

static int
dummy_check_issued_cb(X509_STORE_CTX * ctx, X509 * x, X509 * issuer) {
    return 1;
}

evhtp_res
my_accept_cb(evhtp_connection_t * conn, void * arg) {
    int i = 0;
    STACK_OF (X509) * px509_chain = NULL;
    X509 *            px509       = NULL;
    char              tmp_dn[256];

    printf("post accepted\n");
    if (conn->ssl) {
        /* BUG: Still connected after SSL failed. 
                Example: wrong certificate purpose on the server side (using a
                client cert) AND when the host cert is expired (might be a
                feature :). */
        /* BUG: When the SSL_VERIFY_FAIL_IF_NO_PEER_CERT is enforced, I still
                get here. Clients see: curl: (35) error:14094410:SSL
                routines:SSL3_READ_BYTES:sslv3 alert handshake failure */

        /* Need to have hostname to potentially compare dnsAltNames of the
         * peer's certificate when auth'ed from a machine */
        printf("Got SSL enabled link\n");
        /* Get certificate chain */
        px509_chain = SSL_get_peer_cert_chain(conn->ssl);
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
        /* Get only the peer certificate, not the chain */
        px509 = SSL_get_peer_certificate(conn->ssl);
        if (px509) {
            X509_NAME_oneline(X509_get_subject_name(px509), tmp_dn, 256);
            printf("Subject DN: %s\n", tmp_dn); 
        }
    }
    return EVHTP_RES_200; /* misleading, has nothing to do with HTTP level codes, it chops the connection if !=200 */
}

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

    evhtp_ssl_init(htp, &scfg);

    srand((unsigned)time(NULL));

    evhtp_set_post_accept_cb(htp, my_accept_cb, NULL);

    evhtp_set_cb(htp, "/lcmaps", testcb, NULL);
    evhtp_bind_socket(htp, "0.0.0.0", 8008, 1024);
    event_base_loop(evbase, 0);
    return 0;
}

