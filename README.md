# H-MAC License

A C library for license management using MAC address and expiration date with 256-bit hash.

Tested on Windows 10.

## Requirements

* A C compiler (such as MSVC or MinGW-w64 in Windows or g++ in Linux)
* [CMake](https://cmake.org/) build tool
* (Optional) [Doxygen](https://www.doxygen.nl/) to generate the docuementation

## Building

Building is performed using CMake:

```bash
mkdir build
cd build
cmake ..
cmake --build . [--config Release]
```

Available options:

* `BUILD_SHARED_LIBS`: set to `ON` to build using shared library

Available targets:

* `hmaclic`: shared library with licensening tools

* `getMachineID`: exectuble to generate the machine ID file

* `generateLicense`: exectuble to generate the license file

* `validateLicense`: exectuable to validate the license file

## Documentation

Generate the docuemtnation with Doxygen or look at `include/hmaclic.h`. Also, `src/getMachineMAC.c`, `src/generateLicense.c` and `src/validateLicense.c` may be usefull.
