
include_directories(
    BEFORE
    /usr/include/openssl
    ..
)

set(
    CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -DUSE_TERMIO \
    -DKLUDGELINEMODE \
    -DAUTHENTICATE \
    -DUSE_SSL \
")

add_executable(
    telnet-ssl
    commands.cc
    environ.cc
    genget.cc
    main.cc
    netlink.cc
    network.cc
    ring.cc
    sys_bsd.cc
    telnet.cc
    terminal.cc
    tn3270.cc
    utilities.cc
    glue.cc
    glue2.cc
)
target_link_libraries(
    telnet-ssl
    crypto
    curses
    ssl
    libtelnet
)
install(
    TARGETS telnet-ssl
    DESTINATION ${BIN_DIR}
)

install(
    FILES telnet.1
    DESTINATION ${MAN_DIR}/man1/
    RENAME telnet-ssl.1
)
