
include_directories(
    BEFORE
    /usr/include/openssl
    ..
)

set(CMAKE_C_FLAGS "\
    ${CMAKE_C_FLAGS} \
    -DISSUE_FILE='\"/etc/issue.net\"' \
    -DPARANOID_TTYS \
    -DNO_REVOKE \
    -DKLUDGELINEMODE \
    -DDIAGNOSTICS \
    -DAUTHENTICATE \
    -DLOGIN_WRAPPER='\"/usr/lib/telnetlogin\"' \
    -DUSE_SSL \
")

add_executable(
    in.telnetd
    global.c
    setproctitle.c
    slc.c
    state.c
    sys_term.c
    telnetd.c
    termstat.c
    utility.c
)
target_link_libraries(
    in.telnetd
    ncurses
    util
    ssl
    crypto
    crypt
    libtelnet
)
install(
    TARGETS in.telnetd
    DESTINATION ${SBIN_DIR}
)

install(
    FILES issue.net.5
    DESTINATION ${MAN_DIR}/man5/
)

install(
    FILES telnetd.8
    DESTINATION ${MAN_DIR}/man8/
    RENAME in.telnetd.8
)
