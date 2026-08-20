#ifndef CYGNETPROV_H
#define CYGNETPROV_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cygnet_provider_ctx_st {
    const OSSL_CORE_HANDLE *handle;
} CYGNET_PROVIDER_CTX;

const OSSL_ALGORITHM *cygnet_provider_query_operation(
    void *provider_ctx,
    int operation_id,
    int *no_cache);
void cygnet_provider_unquery_operation(
    void *provider_ctx,
    int operation_id,
    const OSSL_ALGORITHM *algorithms);
const OSSL_PARAM *cygnet_provider_gettable_params(void *provider_ctx);
int cygnet_provider_get_params(void *provider_ctx, OSSL_PARAM params[]);
int cygnet_provider_get_capabilities(
    void *provider_ctx,
    const char *capability,
    OSSL_CALLBACK *callback,
    void *arg);

extern const OSSL_ALGORITHM cygnet_mac_algorithms[];
extern const OSSL_ALGORITHM cygnet_kem_algorithms[];
extern const OSSL_ALGORITHM cygnet_keymgmt_algorithms[];
extern const OSSL_ALGORITHM cygnet_signature_algorithms[];
extern const OSSL_ALGORITHM cygnet_mac_algorithms[];

#ifdef __cplusplus
}
#endif

#endif
