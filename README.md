# Cygnet Provider

Cygnet is an OpenSSL 3 provider scaffold maintained by Sanctum SecOps LLC.

## Scope

This repository provides the provider dispatch structure, capability discovery, and algorithm registration points for Cygnet. The current implementation intentionally exposes no cryptographic algorithms. KEM, key-management, and signature source units are present as integration boundaries for FIPS-aligned implementations.

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Load test

```sh
OPENSSL_MODULES="$PWD/build/provider" ./build/tests/provider_load_test
```

The module name is `cygnetprov`.

## Security boundary

This scaffold is not a FIPS 140-3 validated module and does not claim validation. Production deployment must use an OpenSSL installation whose FIPS provider and configuration are approved for the target environment.
