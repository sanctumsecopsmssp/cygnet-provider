enable_testing()

add_executable(provider_load_test provider_load_test.c)
target_link_libraries(provider_load_test PRIVATE OpenSSL::Crypto)

add_test(NAME provider_load_test COMMAND provider_load_test)
set_tests_properties(provider_load_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:cygnetprov>"
)
