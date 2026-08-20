#include "cygnetprov.h"

#include <openssl/params.h>

#include <stdlib.h>
#include <string.h>

static void cygnet_provider_teardown(void *provider_ctx)
{
    free(provider_ctx);
}

const OSSL_ALGORITHM *cygnet_provider_query_operation(
    void *provider_ctx,
    int operation_id,
    int *no_cache)
{
    (void)provider_ctx;
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEM:
        return cygnet_kem_algorithms;
    case OSSL_OP_KEYMGMT:
        return cygnet_keymgmt_algorithms;
    case OSSL_OP_SIGNATURE:
        return cygnet_signature_algorithms;
    case OSSL_OP_MAC:
        return cygnet_mac_algorithms;
    default:
        return NULL;
    }
}

void cygnet_provider_unquery_operation(
    void *provider_ctx,
    int operation_id,
    const OSSL_ALGORITHM *algorithms)
{
    (void)provider_ctx;
    (void)operation_id;
    (void)algorithms;
}

const OSSL_PARAM *cygnet_provider_gettable_params(void *provider_ctx)
{
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
        OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
        OSSL_PARAM_END
    };

    (void)provider_ctx;
    return parameters;
}

int cygnet_provider_get_params(void *provider_ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *parameter;
    char *name = "CygnetLib";
    char *version = CYGNETPROV_VERSION;
    char *buildinfo = CYGNETPROV_VERSION;
    int status = 1;

    (void)provider_ctx;

    if ((parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(parameter, name)) {
        return 0;
    }
    if ((parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(parameter, version)) {
        return 0;
    }
    if ((parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(parameter, buildinfo)) {
        return 0;
    }
    if ((parameter = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL
        && !OSSL_PARAM_set_int(parameter, status)) {
        return 0;
    }

    return 1;
}

OSSL_provider_init_fn OSSL_provider_init;

int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provider_ctx)
{
    static const OSSL_DISPATCH dispatch_table[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN,
          (void (*)(void))cygnet_provider_teardown },
        { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
          (void (*)(void))cygnet_provider_gettable_params },
        { OSSL_FUNC_PROVIDER_GET_PARAMS,
          (void (*)(void))cygnet_provider_get_params },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
          (void (*)(void))cygnet_provider_query_operation },
        { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION,
          (void (*)(void))cygnet_provider_unquery_operation },
        { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
          (void (*)(void))cygnet_provider_get_capabilities },
        { 0, NULL }
    };
    CYGNET_PROVIDER_CTX *ctx;

    (void)in;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return 0;
    }

    ctx->handle = handle;
    *provider_ctx = ctx;
    *out = dispatch_table;
    return 1;
}
