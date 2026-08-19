#include "cygnetprov.h"

int cygnet_provider_get_capabilities(
    void *provider_ctx,
    const char *capability,
    OSSL_CALLBACK *callback,
    void *arg)
{
    (void)provider_ctx;
    (void)capability;
    (void)callback;
    (void)arg;
    return 0;
}
