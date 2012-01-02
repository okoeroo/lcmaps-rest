#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_openssl.h>
#include "lcmapsd_fullssl.h"

#define LCMAPSD_URI_FULLSSL  "/lcmaps/ssl"


static int lcmapsd_push_peer_certificate_to_chain(STACK_OF(X509) * chain, X509 * cert);

static int lcmapsd_push_peer_certificate_to_chain(STACK_OF(X509) * chain,
                                           X509 * cert) {
    return sk_X509_insert(chain, cert, 0);;
}

static int
lcmapsd_construct_mapping_in_html(struct evbuffer * buf,
                                  uid_t            uid,
                                  gid_t *          pgid_list,
                                  int              npgid,
                                  gid_t *          sgid_list,
                                  int              nsgid,
                                  char *           poolindex) {
    int              i           = 0;

    /* Construct message body */
    evbuffer_add_printf(buf, "<html><body>");
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


#if 0
{"menu": {
  "id": "file",
  "value": "File",
  "popup": {
    "menuitem": [
      {"value": "New", "onclick": "CreateNewDoc()"},
      {"value": "Open", "onclick": "OpenDoc()"},
      {"value": "Close", "onclick": "CloseDoc()"}
    ]
  }
}}
The same text expressed as XML:

<menu id="file" value="File">
  <popup>
    <menuitem value="New" onclick="CreateNewDoc()" />
    <menuitem value="Open" onclick="OpenDoc()" />
    <menuitem value="Close" onclick="CloseDoc()" />
  </popup>
</menu>
#endif


static int
lcmapsd_construct_mapping_in_json(struct evbuffer * buf,
                                  uid_t            uid,
                                  gid_t *          pgid_list,
                                  int              npgid,
                                  gid_t *          sgid_list,
                                  int              nsgid,
                                  char *           poolindex) {
    int              i           = 0;

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


static evhtp_res
lcmapsd_perform_lcmaps(evhtp_request_t * req, STACK_OF(X509) * chain) {
    uid_t            uid         = -1;
    gid_t *          pgid_list   = NULL;
    int              npgid       = 0;
    gid_t *          sgid_list   = NULL;
    int              nsgid       = 0;
    char *           poolindexp  = NULL;
    int              res         = 0;

    if (!chain) {
        return EVHTP_RES_UNAUTH; /* 401 */
    }

    /* Go to LCMAPS */
    if (lcmaps_init(NULL) != 0) {
        /* Unable to initialize LCMAPS, have a look at the config file and
         * logfile */
        return EVHTP_RES_SERVUNAVAIL; /* 503 */
    }
    res = lcmaps_run_with_stack_of_x509_and_return_account(
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
    if (res != 0) {
        return EVHTP_RES_FORBIDDEN; /* 403 */
    }
    if (lcmaps_term() != 0) {
        /* Could not tierdown LCMAPS */
        return EVHTP_RES_SERVERR; /* 500 */
    }

    poolindexp = strdup("mypoolindex");

    /* Construct message body */
    lcmapsd_construct_mapping_in_html(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
    lcmapsd_construct_mapping_in_json(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);

    free(pgid_list);
    free(sgid_list);

    return EVHTP_RES_OK; /* 200 */
}

void
lcmapsd_fullssl_cb(evhtp_request_t * req, void * a) {
    STACK_OF (X509) *px509_chain = NULL;
    X509            *px509       = NULL;
    evhtp_res        lcmaps_res  = 0;

    printf("lcmapsd_fullssl_cb on the URI: \"" LCMAPSD_URI_FULLSSL "\"\n");
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
lcmapsd_fullssl_init(evhtp_t * htp) {
    evhtp_set_cb(htp, LCMAPSD_URI_FULLSSL, lcmapsd_fullssl_cb, NULL);

    return 0;
}

