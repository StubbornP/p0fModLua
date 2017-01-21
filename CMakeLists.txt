cmake_minimum_required(VERSION 3.6)
project(modP0F)

set(CMAKE_C_STANDARD 99)

set( CMAKE_C_FLAGS  ${CMAKE_C_FLAGS} -fPIC)

set(SOURCE_FILES library.c library.h api.c api.h alloc-inl.h config.h debug.h fp_http.c fp_http.h fp_mtu.c fp_mtu.h
        fp_tcp.c fp_tcp.h hash.h languages.h process.c process.h readfp.c readfp.h tcp.h types.h)
add_library(modP0F SHARED ${SOURCE_FILES})