# For more information about using CMake with Android Studio, read the
# documentation https//d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.10.2)

set(LINK_LIBS_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openssl-1.1.1o)
message("--LINK_LIBS_ROOT_DIR ${LINK_LIBS_ROOT_DIR}")

#配置加载头文件
include_directories(${LINK_LIBS_ROOT_DIR}/include)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

# 编译library
add_library( # Sets the name of the library.
        # 设置library名称
        keystore

        # Sets the library as a shared library.
        # 设置library模式
        # SHARED模式会编译so文件，STATIC模式不会编译
        SHARED

        # Provides a relative path to your source file(s).
        # 设置原生代码路径
        src/main/jni/cpp/KeyChain.cpp
        src/main/jni/cpp/KeyStore.cpp
        src/main/jni/cpp/KeyStoreNative.cpp)

#动态方式加载
add_library(openssl SHARED IMPORTED)
add_library(ssl SHARED IMPORTED)

#引入第三方.so库
set_target_properties(openssl PROPERTIES IMPORTED_LOCATION ${LINK_LIBS_ROOT_DIR}/lib/${CMAKE_ANDROID_ARCH_ABI}/libcrypto.so)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION ${LINK_LIBS_ROOT_DIR}/lib/${CMAKE_ANDROID_ARCH_ABI}/libssl.so)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

# 关联library
target_link_libraries( # Specifies the target library.
        keystore
        openssl
        ssl
        android

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})