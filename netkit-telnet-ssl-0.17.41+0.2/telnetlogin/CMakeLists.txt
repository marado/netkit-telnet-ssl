
add_executable(
    telnetlogin
    telnetlogin.c
)
install(
    TARGETS telnetlogin
    DESTINATION ${BIN_DIR}
)

install(
    FILES telnetlogin.8
    DESTINATION ${MAN_DIR}/man8/
)
