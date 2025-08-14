# CMake configuration for SABLE Android JNI library

cmake_minimum_required(VERSION 3.18.1)

project(sable_android)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add Rust target directory
set(SABLE_CORE_LIB "${CMAKE_CURRENT_SOURCE_DIR}/../../target/${ANDROID_ABI}/libsable_core.a")

# Find required libraries
find_library(log-lib log)
find_library(android-lib android)

# Create JNI library
add_library(sable_android SHARED
    src/main/cpp/sable_jni.cpp
    src/main/cpp/android_keystore.cpp
    src/main/cpp/android_biometric.cpp
)

# Include directories
target_include_directories(sable_android PRIVATE
    src/main/cpp/include
    ../../core/src/mobile
)

# Link libraries
target_link_libraries(sable_android
    ${SABLE_CORE_LIB}
    ${log-lib}
    ${android-lib}
)

# Add Rust build dependency
add_custom_command(
    OUTPUT ${SABLE_CORE_LIB}
    COMMAND cargo build --release --target ${RUST_TARGET} --features mobile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../..
    COMMENT "Building SABLE Rust core library"
)

# Set Rust target based on Android ABI
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(RUST_TARGET "aarch64-linux-android")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(RUST_TARGET "armv7-linux-androideabi")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(RUST_TARGET "x86_64-linux-android")
else()
    message(FATAL_ERROR "Unsupported Android ABI: ${ANDROID_ABI}")
endif()
