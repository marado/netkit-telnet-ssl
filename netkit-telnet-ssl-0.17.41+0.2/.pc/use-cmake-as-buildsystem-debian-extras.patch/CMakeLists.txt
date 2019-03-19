cmake_minimum_required(VERSION 3.7)
project(netkit-telnet-ssl)

set(BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin")
set(SBIN_DIR "${CMAKE_INSTALL_PREFIX}/sbin")
set(MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man")

set(USE_GLIBC 1)

set(
    CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -D_GNU_SOURCE \
    -DACCEPT_USERVAR \
    -Wall \
    -Wno-trigraphs \
")
set(
    CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -D_GNU_SOURCE \
    -DACCEPT_USERVAR \
    -Wall \
    -Wno-trigraphs \
")

find_library(USE_TERMCAP lncurses REQUIRED)

add_subdirectory(telnet)
add_subdirectory(telnetd)
add_subdirectory(telnetlogin)
add_subdirectory(libtelnet)
