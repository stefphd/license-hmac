# Licese with MAC address
cmake_minimum_required(VERSION 3.25)

# Set the project name etc
project(hmaclic
        LANGUAGES C
        VERSION 1.0.0
        DESCRIPTION "A C library for licensing using MAC address"
        )

# Options
option(BUILD_SHARED_LIBS "Build using shared library" OFF)

# Doxygen
find_package(Doxygen)

# Configure header file depending on build type
set(CMAKE_HMACLIC_EXPORT_API "#define HMACLIC_EXPORT_API // static library")
if(BUILD_SHARED_LIBS)
set(CMAKE_HMACLIC_EXPORT_API 
"#ifndef HMACLIC_EXPORT_API
    #ifdef _WIN32  // For Windows
        #ifdef BUILD_HMACLIC
            #define HMACLIC_EXPORT_API __declspec(dllexport)
        #else
            #define HMACLIC_EXPORT_API __declspec(dllimport)
        #endif
    #elif defined(__linux__) || defined(__APPLE__)  // For Linux and macOS
        #ifdef BUILD_HMACLIC
            #define HMACLIC_EXPORT_API __attribute__((visibility(\"default\")))
        #else
            #define HMACLIC_EXPORT_API
        #endif
    #else
        #define HMACLIC_EXPORT_API // Fallback for other platforms
    #endif
#endif")
endif()
configure_file(${CMAKE_SOURCE_DIR}/include/hmaclic.in 
    ${CMAKE_SOURCE_DIR}/include/hmaclic.h
    @ONLY)


# License hmaclic
add_library(hmaclic src/hmaclic.c src/sha256.c)
target_include_directories(hmaclic PUBLIC include)
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