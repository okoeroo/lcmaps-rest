#include "lcmapsd_common.h"



#if 0
int
evhtp_kvs_for_each(evhtp_kvs_t * kvs, evhtp_kvs_iterator cb, void * arg) {
    evhtp_kv_t * kv;

    TAILQ_FOREACH(kv, kvs, next) {
        int res;

        if ((res = cb(kv, arg))) {
            return res;
        }
    }

    return 0;
}
#endif



int
lcmapsd_select_return_format(evhtp_request_t *req) {
    const char * format   = NULL;
    const char * accept_h = NULL;

    /* Search the parsed query string for the "?format=" tag */
    if ((format = evhtp_kv_find(req->uri->query, "format"))) {
        if (strcasecmp("json", format) == 0) {
            return TYPE_JSON;
        } else if (strcasecmp("xml", format) == 0) {
            return TYPE_XML;
        } else if (strcasecmp("html", format) == 0) {
            return TYPE_HTML;
        } else {
            return TYPE_UNKNOWN;
        }
    }

    /* Search the HTTP headers for the 'accept:' tag */
    if ((accept_h = evhtp_header_find(req->headers_in, "accept"))) {
        if (strcmp("application/json", accept_h) == 0) {
            return TYPE_JSON;
        } else if (strcmp("text/xml", accept_h) == 0) {
            return TYPE_XML;
        } else if (strcmp("text/html", accept_h) == 0) {
            return TYPE_HTML;
        } else if (strcmp("*/*", accept_h) == 0) {
            return TYPE_JSON;
        } else {
            return TYPE_UNKNOWN;
        }
    }
    /* The default answer is JSON */
    return TYPE_JSON;
}

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


int grid_check_issued_wrapper(X509_STORE_CTX *ctx,X509 *x,X509 *issuer)
/* We change the default callback to use our wrapper and discard errors
   due to GSI proxy chains (ie where users certs act as CAs) */
{
    int ret = 0;

    /* If all is ok, move out of here */
    if ((ret = X509_check_issued(issuer, x)) == X509_V_OK)
        return 1;

    /* Non self-signed certs without signing are ok if they passed
           the other checks inside X509_check_issued. Is this enough? */
    if ((ret == X509_V_ERR_KEYUSAGE_NO_CERTSIGN) &&
        (X509_subject_name_cmp(issuer, x) != 0)) return 1;

    /* If we haven't asked for issuer errors don't set ctx */
#if OPENSSL_VERSION_NUMBER < 0x00908000L
    if (!(ctx->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#else
    if (!(ctx->param->flags & X509_V_FLAG_CB_ISSUER_CHECK)) return 0;
#endif

    ctx->error = ret;
    ctx->current_cert = x;
    ctx->current_issuer = issuer;

    return ctx->verify_cb(0, ctx);
}


/**
 * Note that timegm() is non-standard. Linux manpage advices the following
 * substition instead.
 */
time_t lcmapsd_tm2time_t_in_utc(struct tm *tm)
{
   time_t ret;
   char *tz;

   tz = getenv("TZ");
   setenv("TZ", "", 1);
   tzset();
   ret = mktime(tm);
   if (tz)
       setenv("TZ", tz, 1);
   else
       unsetenv("TZ");
   tzset();

   return ret;
}


int
asn1time_to_time(ASN1_TIME *asn1time, time_t *result)
{
    struct tm tm;
    time_t res = -1;

    if (!asn1time || !asn1time->data || !result)
        return 1;

    memset(&tm, 0, sizeof(struct tm));

    switch (asn1time->type) {
        case V_ASN1_UTCTIME:
            if (sscanf((char *)asn1time->data,
                       "%2d%2d%2d%2d%2d%2dZ",
                       &tm.tm_year, &tm.tm_mon,
                       &tm.tm_mday, &tm.tm_hour,
                       &tm.tm_min, &tm.tm_sec) != 6) {
                return 1;
            }
            tm.tm_mon--;
            if (tm.tm_year < 69) {
                tm.tm_year += 100;
                /* tm.tm_year += 2000; */
            } else {
                tm.tm_year += 1900;
            }
            break;
        case V_ASN1_GENERALIZEDTIME:
            if (sscanf((char *)asn1time->data,
                       "%4d%2d%2d%2d%2d%2dZ",
                       &tm.tm_year, &tm.tm_mon,
                       &tm.tm_mday, &tm.tm_hour,
                       &tm.tm_min, &tm.tm_sec) != 6) {
                return 1;
            }
            break;
        default:
            return 1;
    }

    /* Convert the struct tm to time_t, enforcing UTC */
    res = lcmapsd_tm2time_t_in_utc(&tm);
    *result = res;

    return 0;
}



/******************************************************************************
Function:   x509IsCA
Description:
    Tests if the X509 * cert is a CA certificate or not
    => Example from GridSite
Parameters:
    A X509 pointer
Returns:
    0      : Not a CA cert
    1      : This is a CA cert
******************************************************************************/
int x509IsCA (X509 *cert)
{
    int purpose_id;

    purpose_id = X509_PURPOSE_get_by_sname("sslclient");

    /* final argument to X509_check_purpose() is whether to check for CAness */

    if (X509_check_purpose(cert, purpose_id + X509_PURPOSE_MIN, 1))
        return 1;
    else return 0;
}




/******************************************************************************
Function:       grid_X509_knownCriticalExts
Description:    Check if the Critical Extention known to proxy certificates
                are set and understood.
Parameters:     X509 * cert
Returns:        unsigned long : X509_V_OK (good), X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION (bad)
******************************************************************************/
#define PROXYCERTINFO_OID      "1.3.6.1.5.5.7.1.14"
#define OLD_PROXYCERTINFO_OID  "1.3.6.1.4.1.3536.1.222"

unsigned long grid_X509_knownCriticalExts(X509 *cert)
{
   int  i = 0;
   char critical[80];
   X509_EXTENSION *ex;

   for (i = 0; i < X509_get_ext_count(cert); ++i)
   {
        ex = X509_get_ext(cert, i);

        if (X509_EXTENSION_get_critical(ex) &&
                                 !X509_supported_extension(ex))
        {
            OBJ_obj2txt(critical, sizeof(critical), X509_EXTENSION_get_object(ex), 1);

            if (strcmp(critical, PROXYCERTINFO_OID) == 0)     return X509_V_OK;
            if (strcmp(critical, OLD_PROXYCERTINFO_OID) == 0) return X509_V_OK;

            return X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
        }
   }
   return X509_V_OK;
}



/******************************************************************************
Function:   grid_verifyProxy
Description:
    Tries to verify the proxies in the certstack
******************************************************************************/
unsigned long grid_verifyProxy( STACK_OF(X509) *certstack )
{
    int          i = 0;
    X509       * cert = NULL;
    time_t       now = time((time_t *)NULL);
    time_t       val_time = -1;
    size_t       len = 0;             /* Lengths of issuer and cert DN */
    size_t       len2 = 0;            /* Lengths of issuer and cert DN */
    int          prevIsLimited = 0;   /* previous cert was proxy and limited */
    char         cert_DN   [256];     /* Pointer to current-certificate-in-certstack's DN */
    char         issuer_DN [256];     /* Pointer to issuer-of-current-cert-in-certstack's DN */
    char       * proxy_part_DN = NULL;
    int          depth = sk_X509_num (certstack);
    int          amount_of_CAs = 0;

    if (depth == 0)
    {
        fprintf(stderr, "%s: Error: Empty certificate chain presented!\n", __func__);
        return X509_V_ERR_APPLICATION_VERIFICATION;
    }


    /* And there was (current) time... */
    /* now = time(&now); */


    /* How many CA certs are there in the certstack? */
    for (i = 0; i < depth; i++)
    {
        if (x509IsCA(sk_X509_value(certstack, i)))
            amount_of_CAs++;
    }

#if 0
    fprintf(stderr, "%s: #CA's = %d , depth = %d\n", __func__, amount_of_CAs, depth);
#endif

    /* Check if our certificate chain could hold anything useful, like proxies or EECs */
    if ((amount_of_CAs + 2) > depth)
    {
        if ((depth - amount_of_CAs) > 0)
        {
            fprintf(stderr, "%s: No proxy certificate in certificate stack to check.\n", __func__);
            return X509_V_OK;
        }
        else
        {
            fprintf(stderr, "%s: No personal certificate (neither proxy or user certificate) found in the certficiate stack.", __func__);
            return X509_V_ERR_APPLICATION_VERIFICATION;
        }
    }


    /*
     * Changed this value to start checking the proxy and such and
     * to skip the CA and the user_cert
     */

    for (i = depth - (amount_of_CAs + 2); i >= 0; i--)
    {
        /* Check for X509 certificate and point to it with 'cert' */
        if ( (cert = sk_X509_value(certstack, i)) != NULL )
        {
            X509_NAME_oneline(X509_get_subject_name(cert), cert_DN,   256);
            X509_NAME_oneline(X509_get_issuer_name(cert),  issuer_DN, 256);
            len       = strlen( cert_DN );
            len2      = strlen( issuer_DN );

#if 0
            fprintf(stderr, "%s: Proxy to verify:\n", __func__ );
            fprintf(stderr, "%s:   Issuer DN: %s\n", __func__, issuer_DN );
            fprintf(stderr, "%s:   DN:        %s\n", __func__, cert_DN );
#endif

            if (asn1time_to_time(X509_get_notBefore(cert), &val_time)) {
                return X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
            }
            if (now < val_time) /* When true, then it's expired */
            {
                fprintf(stderr, "%s: Proxy not yet valid.\n", __func__);
                return X509_V_ERR_CERT_NOT_YET_VALID;
            }

            if (asn1time_to_time(X509_get_notAfter(cert), &val_time)) {
                return X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
            }
            if (now > val_time) /* When true, then it's expired */
            {
                fprintf(stderr, "%s: Proxy certificate expired.\n", __func__);
                return X509_V_ERR_CERT_HAS_EXPIRED;
            }

            /* User not allowed to sign shortened DN */
            /* Note: Only true for GT2 proxies */
            if (len2 > len)
            {
                fprintf(stderr, "%s: It is not allowed to sign a shorthened DN.\n", __func__);
                return X509_V_ERR_INVALID_CA;
            }

            /* Proxy subject must begin with issuer. */ /* This is not true in RFC/GT4 proxies */
            if (strncmp(cert_DN, issuer_DN, len2) != 0)
            {
                fprintf(stderr, "%s: Proxy subject must begin with the issuer.\n", __func__);
                return X509_V_ERR_INVALID_CA;
            }

            /* Set pointer to end of base DN in cert_DN */
            proxy_part_DN = &cert_DN[len2];

            /* First attempt at support for Old and New style GSI
               proxies: /CN=anything is ok for now */
            if (strncmp(proxy_part_DN, "/CN=", 4) != 0)
            {
                fprintf(stderr, "%s: Could not find a /CN= structure in the DN, thus it is not a proxy.\n", __func__);
                return X509_V_ERR_INVALID_CA;
            }

            /* The following structures need to be reworked to support for GSI/RFC3820 proxies */
            if ((strncmp(proxy_part_DN, "/CN=proxy", 9) == 0) && (i > 0))
            {
                fprintf(stderr, "%s:  Found old style proxy.\n", __func__);
            }


            if ((strncmp(proxy_part_DN, "/CN=limited proxy", 17) == 0) && (i > 0))
            {
                prevIsLimited = 1;
                fprintf(stderr, "%s:  Found old style limited proxy.\n", __func__);
            }
            else
            {
                if (prevIsLimited)
                {
                    fprintf(stderr, "%s: Proxy chain integrity error. Previous proxy in chain was limited, but this one is a regular proxy.\n", __func__);
                    return X509_V_ERR_INVALID_CA;
                }
            }
#if 0
            fprintf(stderr, "%s:   Proxy is valid\n", __func__);
#endif
        }
    }

    return X509_V_OK;
}





/******************************************************************************
Function:       scas_verify_callback()
Description:    Execute the OpenSSL verify callback
                The ok will be the result of the default verification function
Parameters:     ok, X509_STORE_CTX *
Returns:        int
******************************************************************************/
int scas_verify_callback(int ok, X509_STORE_CTX *store_ctx)
{
    unsigned long   errnum   = X509_STORE_CTX_get_error(store_ctx);
    int             errdepth = X509_STORE_CTX_get_error_depth(store_ctx);
    X509           *cert     = X509_STORE_CTX_get_current_cert(store_ctx);
    STACK_OF(X509) *certstack = NULL;
    char *          cert_DN   = NULL;
    char *          issuer_DN = NULL;

    cert_DN   = X509_NAME_oneline (X509_get_subject_name (cert), NULL, 0);
    issuer_DN = X509_NAME_oneline (X509_get_issuer_name (cert), NULL, 0);

    /* Resolve known error state and flag them as 'ok' */
    if (ok != 1)
    {
        if (errnum == X509_V_ERR_INVALID_CA) ok=1;
        if (errnum == X509_V_ERR_UNABLE_TO_GET_CRL) ok=1;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        /* I don't want to do this, really, but I have yet to figure out
           how to get openssl 0.9.8 to accept proxy certificates when
           opening a new SSL connection...
        */
        if (errnum == X509_V_ERR_INVALID_PURPOSE) ok=1;
#endif
        if (errnum == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
        {
            /* errnum = grid_knownCriticalExts( cert ); */
            errnum = grid_X509_knownCriticalExts (cert);
            store_ctx->error = errnum;
            if (errnum == X509_V_OK) ok=1;
        }
    }


    /*
     * We've now got the last certificate - the identity being used for
     * this connection. At this point we check the whole chain for valid
     * CAs or, failing that, GSI-proxy validity using grid_verifyProxy
     */
    if ( (errdepth == 0) && (ok == 1) )
    {
        certstack = (STACK_OF(X509) *) X509_STORE_CTX_get_chain (store_ctx);

        errnum = grid_verifyProxy (certstack);
        store_ctx->error = errnum;
        if (errnum == X509_V_OK) ok=1;
    }

    if (ok != 1)
    {
        fprintf(stderr, "verify_callback: error message = %s\n",
                X509_verify_cert_error_string (errnum));
    }


    /* The current way of working needs freeing */
    free (cert_DN);
    free (issuer_DN);

    return ok;
}


