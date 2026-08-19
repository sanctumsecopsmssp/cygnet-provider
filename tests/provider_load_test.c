#include <openssl/crypto.h>
#include <openssl/provider.h>

#include <stdio.h>

int main(void)
{
    OSSL_PROVIDER *provider;
    const char *name;

    provider = OSSL_PROVIDER_load(NULL, "cygnetprov");
    if (provider == NULL) {
        fputs("failed to load cygnetprov\n", stderr);
        return 1;
    }

    name = OSSL_PROVIDER_get0_name(provider);
    if (name == NULL || OPENSSL_strcasecmp(name, "cygnetprov") != 0) {
        fputs("loaded provider name did not match cygnetprov\n", stderr);
        OSSL_PROVIDER_unload(provider);
        return 2;
    }

    if (!OSSL_PROVIDER_unload(provider)) {
        fputs("failed to unload cygnetprov\n", stderr);
        return 3;
    }

    return 0;
}
