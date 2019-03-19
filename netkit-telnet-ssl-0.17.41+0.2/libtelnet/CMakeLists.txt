
include_directories(
    BEFORE
    /usr/include/openssl
    .
)

set(
    CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -DUSE_TERMIO \
    -DKLUDGELINEMODE \
    -DAUTHENTICATE \
    -DUSE_SSL \
")

add_library(
    libtelnet
    auth.c
    misc.c
    ssl.c
    sslapp.c
)
