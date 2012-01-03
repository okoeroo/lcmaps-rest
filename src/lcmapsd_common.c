#include "lcmapsd_common.h"


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

int
lcmapsd_construct_error_reply_in_html(struct evbuffer *buf,
                                      const char * title,
                                      const char * body_fmt,
                                      ...) {
    va_list ap;

    evbuffer_add_printf(buf, "<html><head><title>%s</title></head><body>\n", PACKAGE_NAME);
    if (title) {
        evbuffer_add_printf(buf, "<h1>%s: %s</h1>\n", PACKAGE_NAME, title);
    }
    if (body_fmt) {
        va_start(ap, body_fmt);
        evbuffer_add_vprintf(buf, body_fmt, ap);
        va_end(ap);
    }
    evbuffer_add_printf(buf, "\n</body></html>\n");
    return 0;
}

int
lcmapsd_construct_mapping_in_html(struct evbuffer *buf,
                                  uid_t            uid,
                                  gid_t *          pgid_list,
                                  int              npgid,
                                  gid_t *          sgid_list,
                                  int              nsgid,
                                  char *           poolindex) {
    int i = 0;

    /* Construct message body */
    evbuffer_add_printf(buf, "<html><body>\n");
    evbuffer_add_printf(buf, "uid: %d<br>\n", uid);
    for (i = 0; i < npgid; i++) {
        evbuffer_add_printf(buf, "gid: %d<br>\n", pgid_list[i]);
    }
    for (i = 0; i < nsgid; i++) {
        evbuffer_add_printf(buf, "secondary gid: %d<br>\n", sgid_list[i]);
    }
    if (poolindex) {
        evbuffer_add_printf(buf, "poolindex: %s<br>\n", poolindex);
    }
    evbuffer_add_printf(buf, "</body></html>\n");

    return 0;
}

int
lcmapsd_construct_mapping_in_xml(struct evbuffer * buf,
                                 uid_t             uid,
                                 gid_t *           pgid_list,
                                 int               npgid,
                                 gid_t *           sgid_list,
                                 int               nsgid,
                                 char *            poolindex) {
    int i = 0;

    /* Construct message body */
    evbuffer_add_printf(buf, "<!DOCTYPE glossary PUBLIC \"-//OASIS//DTD DocBook V3.1//EN\">\n");
    evbuffer_add_printf(buf, "<lcmaps>\n");
    evbuffer_add_printf(buf, "  <mapping>\n");
    evbuffer_add_printf(buf, "    <posix>\n");
    evbuffer_add_printf(buf, "      <uid>\n");
    evbuffer_add_printf(buf, "        <id>%d</id>\n", uid);
    evbuffer_add_printf(buf, "      </uid>\n");
    if (npgid > 0) {
        evbuffer_add_printf(buf, "      <pgid>\n");
        evbuffer_add_printf(buf, "        <id>%d</id>\n", pgid_list[0]);
        evbuffer_add_printf(buf, "      </pgid>\n");
    }
    if (nsgid > 0) {
        evbuffer_add_printf(buf, "      <sgid>\n");
        evbuffer_add_printf(buf, "        <array>\n");
        for (i = 0; i < nsgid; i++) {
            evbuffer_add_printf(buf, "          <id>%d</id>\n", sgid_list[i]);
        }
        evbuffer_add_printf(buf, "        </array>\n");
        evbuffer_add_printf(buf, "      </sgid>\n");
    }
    evbuffer_add_printf(buf, "    </posix>\n");
    if (poolindex) {
        evbuffer_add_printf(buf, "    <poolindex>%s</poolindex>\n", poolindex);
    }
    evbuffer_add_printf(buf, "  </mapping>\n");
    evbuffer_add_printf(buf, "</lcmaps>\n");
    return 0;
}


int
lcmapsd_construct_mapping_in_json(struct evbuffer *buf,
                                  uid_t            uid,
                                  gid_t *          pgid_list,
                                  int              npgid,
                                  gid_t *          sgid_list,
                                  int              nsgid,
                                  char *           poolindex) {
    int i = 0;

    /* Construct message body */
    evbuffer_add_printf(buf, "{\"lcmaps\": {\n");
    evbuffer_add_printf(buf, "    \"mapping\": {\n");
    evbuffer_add_printf(buf, "        \"posix\": {\n");
    evbuffer_add_printf(buf, "            \"uid\": { \"id\": %d }%s\n", uid, npgid || nsgid ? "," : "");
    if (npgid > 0) {
    evbuffer_add_printf(buf, "            \"pgid\": { \"id\": %d }%s\n", pgid_list[0], nsgid ? "," : "");
    }
    evbuffer_add_printf(buf, "            \"sgid\": [\n");
    for (i = 0; i < nsgid; i++) {
        evbuffer_add_printf(buf, "                { \"id\": %d }%s\n", sgid_list[i], (i + 1) < nsgid ? "," : "" );
    }
    evbuffer_add_printf(buf, "                    ]\n");

    evbuffer_add_printf(buf, "            }%s\n", poolindex ? "," : "");
    if (poolindex) {
        evbuffer_add_printf(buf, "        \"poolindex\": \"%s\"\n", poolindex);
    }
    evbuffer_add_printf(buf, "        }\n");
    evbuffer_add_printf(buf, "    }\n");
    evbuffer_add_printf(buf, "}\n");

    return 0;
}
