# Licese with MAC address
cmake_minimum_required(VERSION 3.25)

# Set the project name etc
project(hmaclic
        LANGUAGES C
        VERSION 1.0.0
        DESCRIPTION "A C library for licensing using MAC address"
        )

# Doxygen
find_package(Doxygen)

# OpenSSL lib
find_package(OpenSSL REQUIRED)
# Create interface library for OpenSSL
add_library(openssl INTERFACE)
target_include_directories(openssl INTERFACE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(openssl INTERFACE ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

# License hmaclic
add_library(hmaclic SHARED src/hmaclic.c)
target_include_directories(hmaclic PUBLIC include)
target_link_libraries(hmaclic PRIVATE openssl)
set_target_properties(hmaclic PROPERTIES PUBLIC_HEADER include/hmaclic.h)
target_compile_definitions(hmaclic PRIVATE BUILD_HMACLIC)

# Get machine MAC address exe
add_executable(getMachineID src/getMachineID.c)
target_link_libraries(getMachineID PRIVATE hmaclic)

# Generate license exe
add_executable(generateLicense src/generateLicense.c)
target_link_libraries(generateLicense PRIVATE hmaclic)

# Validate license lib
add_executable(validateLicense src/validateLicense.c)
target_link_libraries(validateLicense PRIVATE hmaclic)

# Docs
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile 
         @ONLY)
    add_custom_target(docs ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
endif(DOXYGEN_FOUND)

# Install
install(TARGETS hmaclic getMachineID generateLicense validateLicense)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs COMPONENT docs DESTINATION ./)