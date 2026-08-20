enable_testing()

find_file(OPENSSL_FIPSMODULE_CNF
    NAMES fipsmodule.cnf
    PATHS /etc/ssl /usr/lib/ssl /usr/local/ssl
)

add_executable(provider_load_test provider_load_test.c)
target_link_libraries(provider_load_test PRIVATE OpenSSL::Crypto)
add_test(NAME provider_load_test COMMAND provider_load_test)
set_tests_properties(provider_load_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:cygnetprov>"
)

add_executable(mac_forward_test mac_forward_test.c)
target_link_libraries(mac_forward_test PRIVATE OpenSSL::Crypto)
add_test(NAME mac_forward_test COMMAND mac_forward_test)

if(OPENSSL_FIPSMODULE_CNF)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/openssl-cygnet-test.cnf.in"
        "${CMAKE_CURRENT_BINARY_DIR}/openssl-cygnet-test.cnf.stage"
        @ONLY
    )
    file(GENERATE
        OUTPUT "${CMAKE_BINARY_DIR}/openssl-cygnet-test.cnf"
        INPUT  "${CMAKE_CURRENT_BINARY_DIR}/openssl-cygnet-test.cnf.stage"
    )
    set_tests_properties(mac_forward_test PROPERTIES
        ENVIRONMENT "OPENSSL_CONF=${CMAKE_BINARY_DIR}/openssl-cygnet-test.cnf"
    )
else()
    message(WARNING "fipsmodule.cnf not found; disabling mac_forward_test.")
    set_tests_properties(mac_forward_test PROPERTIES DISABLED TRUE)
endif()
