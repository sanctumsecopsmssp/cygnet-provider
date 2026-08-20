add_library(cygnetprov MODULE
    cygnetprov.c
    cygnetprov_capabilities.c
    cygnetprov_mac.c
    cygnetprov_kem.c
    cygnetprov_kmgmt.c
    cygnetprov_mac.c
    cygnetprov_sig.c
)

target_include_directories(cygnetprov PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(cygnetprov PRIVATE OpenSSL::Crypto)

set_target_properties(cygnetprov PROPERTIES
    PREFIX ""
    OUTPUT_NAME "cygnetprov"
)

set(CYGNET_TEST_MODULE "${CMAKE_CURRENT_BINARY_DIR}/cygnetprov.so")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/openssl-cygnet-test.cnf.in"
    "${CMAKE_BINARY_DIR}/openssl-cygnet-test.cnf"
    @ONLY
)

if(WIN32)
    target_sources(cygnetprov PRIVATE cygnetprov.def)
endif()
