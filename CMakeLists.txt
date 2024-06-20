# Licese with H-MACs

cmake_minimum_required(VERSION 3.25)

# Set the project name etc
project(license-hmac
        LANGUAGES C CXX
        VERSION 0.0.1
        DESCRIPTION "A C++ library for licensing using MAC address"
        )

# Set the C++ standard to C++ 11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
set(LIC_PRIVATE_KEY "\"a-very-long-private-key-that-should-remain-unknown-to-the-enduser-012345689-!@#?^\"" CACHE STRING "Private key of license generation/validation")

# OpenSSL lib
find_package(OPENSSL REQUIRED)
# Create interface library for OpenSSL
add_library(openssl INTERFACE)
target_include_directories(openssl 
                        INTERFACE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(openssl 
                      INTERFACE ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

# License utils lib
add_library(licutils SHARED
			src/licutils.cpp)
target_include_directories(licutils
				PUBLIC include		
			)
target_link_libraries(licutils
				PRIVATE openssl
				)
target_compile_definitions(licutils
				PRIVATE DLib_EXPORTS)

# Get machine MAC address exe
add_executable(getMachineID 
				src/getMachineID.cpp
				)
target_link_libraries(getMachineID
				PRIVATE licutils
				)

# Generate license exe
add_executable(generateLicense 
				src/generateLicense.cpp
				)
target_link_libraries(generateLicense
				PRIVATE licutils
				)
target_compile_definitions(generateLicense
				PRIVATE PRIVATE_KEY=${LIC_PRIVATE_KEY}
				)

# Validate license lib
add_executable(validateLicense 
				src/validateLicense.cpp
				)
target_link_libraries(validateLicense
				PRIVATE licutils
				)
target_compile_definitions(validateLicense
				PRIVATE PRIVATE_KEY=${LIC_PRIVATE_KEY}
				)
