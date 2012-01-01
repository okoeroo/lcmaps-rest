#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_openssl.h>

#include "lcmapsd_fullssl.h"


int lcmapsd_push_peer_certificate_to_chain(STACK_OF(X509) * chain, X509 * cert);

int lcmapsd_push_peer_certificate_to_chain(STACK_OF(X509) * chain,
                                           X509 * cert) {
    printf("Push peer certificate into the chain\n");
    return sk_X509_insert(chain, cert, 0);;
}

void
lcmapsd_fullssl_cb(evhtp_request_t * req, void * a) {
    STACK_OF (X509) *px509_chain = NULL;
    X509            *px509       = NULL;
    int              i           = 0;

    uid_t            uid         = -1;
    gid_t *          pgid_list   = NULL;
    int              npgid       = 0;
    gid_t *          sgid_list   = NULL;
    int              nsgid       = 0;
    char *           poolindexp  = 0;

    printf("lcmapsd_fullssl_cb on the URI: \"/lcmaps/ssl\"\n");
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

        /* Get only the peer certificate, not the chain */
        px509 = SSL_get_peer_certificate(req->conn->ssl);
        if (!px509) {
            printf("No peer certificate. Full SSL is impossible\n");
            evhtp_send_reply(req, EVHTP_RES_IAMATEAPOT);
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

        /* Got to LCMAPS */
        lcmaps_init(NULL);
        lcmaps_run_with_stack_of_x509_and_return_account(px509_chain,
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
        lcmaps_term();
    }

    /* Construct message body */
    evbuffer_add_printf(req->buffer_out, "<html><body>");
    evbuffer_add_printf(req->buffer_out, "uid: %d<br>\n", uid);
    for (i = 0; i < npgid; i++) {
        evbuffer_add_printf(req->buffer_out, "gid: %d<br>\n", pgid_list[i]);
    }
    for (i = 0; i < nsgid; i++) {
        evbuffer_add_printf(req->buffer_out, "secondary gid: %d<br>\n", sgid_list[i]);
    }
    if (poolindexp) {
        evbuffer_add_printf(req->buffer_out, "poolindex: %s\n", poolindexp);
    }
    evbuffer_add_printf(req->buffer_out, "</body></html>");

    evhtp_send_reply(req, EVHTP_RES_OK);
    return;
}

int
lcmapsd_fullssl_init(evhtp_t * htp) {
    evhtp_set_cb(htp, "/lcmaps/ssl", lcmapsd_fullssl_cb, NULL);

    return 0;
}

