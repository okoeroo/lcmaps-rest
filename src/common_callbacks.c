#include "common_callbacks.h"


int
dummy_ssl_verify_callback(int ok, X509_STORE_CTX * x509_store) {
    return 1;
}

int
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

