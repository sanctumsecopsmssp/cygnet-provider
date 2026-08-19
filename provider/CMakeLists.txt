add_library(cygnetprov MODULE
    cygnetprov.c
    cygnetprov_capabilities.c
    cygnetprov_mac.c
    cygnetprov_kem.c
    cygnetprov_kmgmt.c
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

if(WIN32)
    target_sources(cygnetprov PRIVATE cygnetprov.def)
endif()
