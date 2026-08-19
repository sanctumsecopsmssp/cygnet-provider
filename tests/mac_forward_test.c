#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <string.h>

static int cygnet_compute_mac(
    const char *algorithm,
    const char *propq,
    const char *digest,
    const unsigned char *key,
    size_t keylen,
    const unsigned char *message,
    size_t messagelen,
    unsigned char *out,
    size_t outsize,
    size_t *outlen,
    const char **servicing_provider)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, algorithm, propq);
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    const OSSL_PROVIDER *prov = NULL;
    int ok = 0;

    if (mac == NULL) {
        fprintf(stderr, "fetch failed: %s [%s]\n", algorithm, propq);
        return 0;
    }

    prov = EVP_MAC_get0_provider(mac);
    *servicing_provider =
        (prov != NULL) ? OSSL_PROVIDER_get0_name(prov) : "unknown";

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MAC_CTX_new failed: %s\n", algorithm);
        goto done;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, keylen, params) != 1) {
        fprintf(stderr, "EVP_MAC_init failed: %s\n", algorithm);
        goto done;
    }
    if (EVP_MAC_update(ctx, message, messagelen) != 1) {
        fprintf(stderr, "EVP_MAC_update failed: %s\n", algorithm);
        goto done;
    }
    if (EVP_MAC_final(ctx, out, outlen, outsize) != 1) {
        fprintf(stderr, "EVP_MAC_final failed: %s\n", algorithm);
        goto done;
    }
    ok = 1;

done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

int main(void)
{
    static const unsigned char key[32] = {
        0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72,
        0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa,
        0x0c, 0x1d, 0x2e, 0x3f, 0x40, 0x51, 0x62, 0x73,
        0x84, 0x95, 0xa6, 0xb7, 0xc8, 0xd9, 0xea, 0xfb
    };
    static const unsigned char message[] =
        "sanctum cygnet mac forwarding validation";
    unsigned char reference[64];
    unsigned char forwarded[64];
    size_t reference_len = 0;
    size_t forwarded_len = 0;
    const char *reference_provider = "unknown";
    const char *forwarded_provider = "unknown";

    if (!OSSL_PROVIDER_available(NULL, "fips")) {
        fprintf(stderr, "fips provider unavailable\n");
        return 1;
    }
    if (!OSSL_PROVIDER_available(NULL, "cygnet")) {
        fprintf(stderr, "cygnet provider unavailable\n");
        return 1;
    }

    if (!cygnet_compute_mac("HMAC", "provider=fips", "SHA2-256",
                            key, sizeof(key),
                            message, sizeof(message) - 1,
                            reference, sizeof(reference), &reference_len,
                            &reference_provider)) {
        return 1;
    }

    if (!cygnet_compute_mac("CYGNET-HMAC", "provider=cygnet", "SHA2-256",
                            key, sizeof(key),
                            message, sizeof(message) - 1,
                            forwarded, sizeof(forwarded), &forwarded_len,
                            &forwarded_provider)) {
        return 1;
    }

    printf("reference provider: %s (%zu bytes)\n",
           reference_provider, reference_len);
    printf("forwarded provider: %s (%zu bytes)\n",
           forwarded_provider, forwarded_len);

    if (reference_len != forwarded_len) {
        fprintf(stderr, "length mismatch: %zu != %zu\n",
                reference_len, forwarded_len);
        return 1;
    }
    if (memcmp(reference, forwarded, reference_len) != 0) {
        fprintf(stderr, "mac mismatch\n");
        return 1;
    }
    if (strcmp(forwarded_provider, "cygnet") != 0) {
        fprintf(stderr, "unexpected servicing provider: %s\n",
                forwarded_provider);
        return 1;
    }

    printf("CYGNET-HMAC matches FIPS HMAC over %zu bytes\n", reference_len);
    return 0;
}
