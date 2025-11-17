cmake_minimum_required(VERSION 3.16)
project(cmakeTest)
# 设置C++标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(main main.cpp SimpleIndex.cpp) 

find_package(libOTe REQUIRED)
find_package(OpenSSL REQUIRED)

set(CMAKE_BUILD_TYPE Release)

target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread)

target_link_libraries(main 
    oc::libOTe
    pthread
    OpenSSL::Crypto
    OpenSSL::SSL
)

# set any other operties like cpp version
