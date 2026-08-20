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

if(APPLE)
    set(CYGNET_MODULE_SUFFIX ".dylib")
elseif(WIN32)
    set(CYGNET_MODULE_SUFFIX ".dll")
else()
    set(CYGNET_MODULE_SUFFIX ".so")
endif()

set_target_properties(cygnetprov PROPERTIES
    PREFIX ""
    OUTPUT_NAME "cygnetprov"
    SUFFIX "${CYGNET_MODULE_SUFFIX}"
)

set(CYGNET_FIPS_MODULE "/usr/lib/x86_64-linux-gnu/ossl-modules-3/fips.so"
    CACHE FILEPATH "Path to the FIPS provider module")

set(CYGNET_TEST_MODULE "${CMAKE_CURRENT_BINARY_DIR}/cygnetprov${CYGNET_MODULE_SUFFIX}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/openssl-cygnet-test.cnf.in"
    "${CMAKE_BINARY_DIR}/openssl-cygnet-test.cnf"
    @ONLY
)

if(WIN32)
    target_sources(cygnetprov PRIVATE cygnetprov.def)
endif()

target_compile_definitions(cygnetprov PRIVATE
  CYGNETPROV_VERSION="${PROJECT_VERSION}")
