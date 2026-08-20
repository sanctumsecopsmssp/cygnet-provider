enable_testing()

add_executable(provider_load_test provider_load_test.c)
target_link_libraries(provider_load_test PRIVATE OpenSSL::Crypto)

add_test(NAME provider_load_test COMMAND provider_load_test)
set_tests_properties(provider_load_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:cygnetprov>"
)

add_executable(mac_forward_test mac_forward_test.c)
target_link_libraries(mac_forward_test PRIVATE OpenSSL::Crypto)

add_test(NAME mac_forward_test COMMAND mac_forward_test)
set_tests_properties(mac_forward_test PROPERTIES
    ENVIRONMENT "OPENSSL_CONF=${CMAKE_BINARY_DIR}/openssl-cygnet-test.cnf"
)
