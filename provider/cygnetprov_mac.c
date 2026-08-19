#include "cygnetprov.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

#define CYGNET_MAC_BACKEND_PROPQ "provider=fips"
#define CYGNET_MAC_PROPERTIES    "provider=cygnet,fips=yes"

typedef struct cygnet_mac_ctx_st {
    const char *backend_name;
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
} CYGNET_MAC_CTX;

static void cygnet_mac_freectx(void *vctx)
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    if (cctx == NULL) {
        return;
    }
    EVP_MAC_CTX_free(cctx->ctx);
    EVP_MAC_free(cctx->mac);
    free(cctx);
}

static void *cygnet_mac_newctx_backend(const char *backend_name)
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)calloc(1, sizeof(*cctx));

    if (cctx == NULL) {
        return NULL;
    }
    cctx->backend_name = backend_name;
    cctx->mac = EVP_MAC_fetch(NULL, backend_name, CYGNET_MAC_BACKEND_PROPQ);
    if (cctx->mac == NULL) {
        cygnet_mac_freectx(cctx);
        return NULL;
    }
    cctx->ctx = EVP_MAC_CTX_new(cctx->mac);
    if (cctx->ctx == NULL) {
        cygnet_mac_freectx(cctx);
        return NULL;
    }
    return cctx;
}

static void *cygnet_mac_newctx_hmac(void *provider_ctx)
{
    (void)provider_ctx;
    return cygnet_mac_newctx_backend("HMAC");
}

static void *cygnet_mac_newctx_cmac(void *provider_ctx)
{
    (void)provider_ctx;
    return cygnet_mac_newctx_backend("CMAC");
}

static void *cygnet_mac_newctx_kmac128(void *provider_ctx)
{
    (void)provider_ctx;
    return cygnet_mac_newctx_backend("KMAC-128");
}

static void *cygnet_mac_newctx_kmac256(void *provider_ctx)
{
    (void)provider_ctx;
    return cygnet_mac_newctx_backend("KMAC-256");
}

static void *cygnet_mac_dupctx(void *vsrc)
{
    CYGNET_MAC_CTX *src = (CYGNET_MAC_CTX *)vsrc;
    CYGNET_MAC_CTX *dst;

    if (src == NULL || src->mac == NULL || src->ctx == NULL) {
        return NULL;
    }
    dst = (CYGNET_MAC_CTX *)calloc(1, sizeof(*dst));
    if (dst == NULL) {
        return NULL;
    }
    dst->backend_name = src->backend_name;
    if (EVP_MAC_up_ref(src->mac) != 1) {
        free(dst);
        return NULL;
    }
    dst->mac = src->mac;
    dst->ctx = EVP_MAC_CTX_dup(src->ctx);
    if (dst->ctx == NULL) {
        EVP_MAC_free(dst->mac);
        free(dst);
        return NULL;
    }
    return dst;
}

static int cygnet_mac_init(
    void *vctx,
    const unsigned char *key,
    size_t keylen,
    const OSSL_PARAM params[])
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    if (cctx == NULL || cctx->ctx == NULL) {
        return 0;
    }
    return EVP_MAC_init(cctx->ctx, key, keylen, params);
}

static int cygnet_mac_update(void *vctx, const unsigned char *in, size_t inl)
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    if (cctx == NULL || cctx->ctx == NULL) {
        return 0;
    }
    return EVP_MAC_update(cctx->ctx, in, inl);
}

static int cygnet_mac_final(
    void *vctx,
    unsigned char *out,
    size_t *outl,
    size_t outsize)
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    if (cctx == NULL || cctx->ctx == NULL) {
        return 0;
    }
    return EVP_MAC_final(cctx->ctx, out, outl, outsize);
}

static const OSSL_PARAM cygnet_mac_known_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *cygnet_mac_gettable_ctx_params(
    void *vctx,
    void *provider_ctx)
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    (void)provider_ctx;
    if (cctx != NULL && cctx->mac != NULL) {
        return EVP_MAC_gettable_ctx_params(cctx->mac);
    }
    return cygnet_mac_known_ctx_params;
}

static const OSSL_PARAM *cygnet_mac_settable_ctx_params(
    void *vctx,
    void *provider_ctx)
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    (void)provider_ctx;
    if (cctx != NULL && cctx->mac != NULL) {
        return EVP_MAC_settable_ctx_params(cctx->mac);
    }
    return cygnet_mac_known_ctx_params;
}

static int cygnet_mac_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    if (cctx == NULL || cctx->ctx == NULL) {
        return 0;
    }
    return EVP_MAC_CTX_get_params(cctx->ctx, params);
}

static int cygnet_mac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    CYGNET_MAC_CTX *cctx = (CYGNET_MAC_CTX *)vctx;

    if (cctx == NULL || cctx->ctx == NULL) {
        return 0;
    }
    return EVP_MAC_CTX_set_params(cctx->ctx, params);
}

#define CYGNET_MAC_DISPATCH(tag, newctx_fn)                                    \
static const OSSL_DISPATCH cygnet_mac_functions_##tag[] = {                    \
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))newctx_fn },                       \
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))cygnet_mac_dupctx },               \
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))cygnet_mac_freectx },             \
    { OSSL_FUNC_MAC_INIT, (void (*)(void))cygnet_mac_init },                   \
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))cygnet_mac_update },               \
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))cygnet_mac_final },                 \
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,                                       \
      (void (*)(void))cygnet_mac_gettable_ctx_params },                        \
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,                                       \
      (void (*)(void))cygnet_mac_settable_ctx_params },                        \
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,                                            \
      (void (*)(void))cygnet_mac_get_ctx_params },                             \
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,                                            \
      (void (*)(void))cygnet_mac_set_ctx_params },                             \
    { 0, NULL }                                                                \
}

CYGNET_MAC_DISPATCH(hmac, cygnet_mac_newctx_hmac);
CYGNET_MAC_DISPATCH(cmac, cygnet_mac_newctx_cmac);
CYGNET_MAC_DISPATCH(kmac128, cygnet_mac_newctx_kmac128);
CYGNET_MAC_DISPATCH(kmac256, cygnet_mac_newctx_kmac256);

const OSSL_ALGORITHM cygnet_mac_algorithms[] = {
    { "CYGNET-HMAC", CYGNET_MAC_PROPERTIES, cygnet_mac_functions_hmac,
      "CygnetLib HMAC serviced by the FIPS provider" },
    { "CYGNET-CMAC", CYGNET_MAC_PROPERTIES, cygnet_mac_functions_cmac,
      "CygnetLib CMAC serviced by the FIPS provider" },
    { "CYGNET-KMAC-128", CYGNET_MAC_PROPERTIES, cygnet_mac_functions_kmac128,
      "CygnetLib KMAC-128 serviced by the FIPS provider" },
    { "CYGNET-KMAC-256", CYGNET_MAC_PROPERTIES, cygnet_mac_functions_kmac256,
      "CygnetLib KMAC-256 serviced by the FIPS provider" },
    { NULL, NULL, NULL, NULL }
};
