#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <lcmaps/lcmaps_basic.h>
#include "lcmapsd_common.h"
#include "lcmapsd_httprest.h"

#define LCMAPSD_HTTP_URI         "/lcmaps/mapping/rest"
#define LCMAPSD_HTTP_BIND_IP     "0.0.0.0"
#define LCMAPSD_HTTP_BIND_PORT   8008
#define LCMAPSD_HTTP_LISTENERS   1024

#define LCMAPSD_SSLHTTP_URI         LCMAPSD_HTTP_URI
#define LCMAPSD_SSLHTTP_BIND_IP     LCMAPSD_HTTP_BIND_IP
#define LCMAPSD_SSLHTTP_BIND_PORT   7443
#define LCMAPSD_SSLHTTP_LISTENERS   LCMAPSD_HTTP_LISTENERS


static evhtp_res lcmapsd_perform_lcmaps_from_uri(evhtp_request_t *);
static void lcmapsd_httprest_cb(evhtp_request_t *, void *);

static evhtp_res
lcmapsd_perform_lcmaps_from_uri(evhtp_request_t * req) {
    evhtp_res   resp_code   = 0;
    uid_t       uid         = -1;
    gid_t *     pgid_list   = NULL;
    int         npgid       = 0;
    gid_t *     sgid_list   = NULL;
    int         nsgid       = 0;
    /* char *       poolindexp  = NULL; */
    int         lcmaps_res  = 0;
    const char *format      = NULL;
    const char *subjectdn   = NULL;
    unsigned char * userdn  = NULL;
    char  **    fqans       = NULL;
    int         nfqan       = 0;
    char *      poolindexp  = NULL;

    /* Construct message body */
    subjectdn = evhtp_kv_find(req->uri->query, "subjectdn");
    if (!subjectdn) {
        /* Fail, MUST have a subject DN */
        lcmapsd_construct_error_reply_in_html(req->buffer_out,
                                              "Missing Subject DN",
                                              "The URI \"%s\" requires a query to \"?subjectdn=<value>\".",
                                              LCMAPSD_HTTP_URI);
        resp_code = EVHTP_RES_BADREQ; /* 400 */
        goto end;
    }

    userdn = calloc(1, strlen(subjectdn) + 1); /* Encoded is always more then not encoded */
    if (evhtp_unescape_string(&userdn, (unsigned char *)subjectdn, strlen(subjectdn)) != 0) {
        /* Unparseable */
        printf ("Parse error\n");
    }

    /* TODO: Add FQAN query parsing */

    /* Go to LCMAPS */
    if (lcmaps_init(NULL) != 0) {
        /* Unable to initialize LCMAPS, have a look at the config file and
         * logfile */
        resp_code = EVHTP_RES_SERVUNAVAIL; /* 503 */
        goto end;
    }
    lcmaps_res = lcmaps_run_with_fqans_and_return_account(
                        userdn,
                        fqans,
                        nfqan,
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
            evhtp_headers_add_header(req->headers_out,
                                     evhtp_header_new("Content-Type", "application/json", 0, 0));
        } else if (strcasecmp("xml", format) == 0) {
            lcmapsd_construct_mapping_in_xml(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
            evhtp_headers_add_header(req->headers_out,
                                     evhtp_header_new("Content-Type", "text/xml", 0, 0));
        } else if (strcasecmp("html", format) == 0) {
            lcmapsd_construct_mapping_in_html(req->buffer_out, uid, pgid_list, npgid, sgid_list, nsgid, poolindexp);
            evhtp_headers_add_header(req->headers_out,
                                     evhtp_header_new("Content-Type", "text/html", 0, 0));
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
        evhtp_headers_add_header(req->headers_out,
                                 evhtp_header_new("Content-Type", "application/json", 0, 0));
    }
    resp_code = EVHTP_RES_OK; /* 200 */

end:
    free(pgid_list);
    free(sgid_list);

    return resp_code;
}

static void
lcmapsd_httprest_cb(evhtp_request_t * req, void * a) {
    evhtp_res        lcmaps_res  = 0;

    /* printf("%s on the URI: \"" LCMAPSD_HTTP_URI "\"\n", __func__); */
    if (!req) {
        printf("No request object! - problem in evhtp/libevent\n");
        return;
    }
    if (!req->conn) {
        printf("No connection object in request object - problem in evhtp/libevent\n");
        return;
    }

    lcmaps_res = lcmapsd_perform_lcmaps_from_uri(req);
    evhtp_send_reply(req, lcmaps_res);
    return;
}

int
lcmapsd_httprest_init(evbase_t * evbase) {
    evhtp_t  * ssl_htp    = evhtp_new(evbase, NULL);
    evhtp_t  * nonssl_htp = evhtp_new(evbase, NULL);
    evhtp_ssl_cfg_t scfg = {
            .pemfile            = "/Users/okoeroo/dvl/certs/ca/test_localhost_with_subjectAltName/hostcert.pem",
            .privfile           = "/Users/okoeroo/dvl/certs/ca/test_localhost_with_subjectAltName/hostkey.pem",
            .cafile             = NULL,
            .capath             = "/etc/grid-security/certificates/",
            .ciphers            = "ALL:!ADH:!LOW:!EXP:@STRENGTH",
            .ssl_opts           = SSL_OP_NO_SSLv2,
            .verify_peer        = SSL_VERIFY_NONE,
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

    evhtp_ssl_init(ssl_htp, &scfg);
    evhtp_set_cb(ssl_htp, LCMAPSD_SSLHTTP_URI, lcmapsd_httprest_cb, NULL);
    if (evhtp_bind_socket(ssl_htp, LCMAPSD_SSLHTTP_BIND_IP, LCMAPSD_SSLHTTP_BIND_PORT, LCMAPSD_SSLHTTP_LISTENERS) != 0) {
        printf("Error: couldn't bind the socket for the URI \"%s\" using SSL on IP \"%s\" and port \"%d\" with %d listeners\n",
                LCMAPSD_SSLHTTP_URI,
                LCMAPSD_SSLHTTP_BIND_IP,
                LCMAPSD_SSLHTTP_BIND_PORT,
                LCMAPSD_SSLHTTP_LISTENERS);
    }

    evhtp_set_cb(nonssl_htp, LCMAPSD_HTTP_URI, lcmapsd_httprest_cb, NULL);
    if (evhtp_bind_socket(nonssl_htp, LCMAPSD_HTTP_BIND_IP, LCMAPSD_HTTP_BIND_PORT, LCMAPSD_HTTP_LISTENERS) != 0) {
        printf("Error: couldn't bind the socket for the URI \"%s\" without SSL on IP \"%s\" and port \"%d\" with %d listeners\n",
                LCMAPSD_HTTP_URI,
                LCMAPSD_HTTP_BIND_IP,
                LCMAPSD_HTTP_BIND_PORT,
                LCMAPSD_HTTP_LISTENERS);
    }
    return 0;
}

