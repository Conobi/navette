#!/bin/sh
if [ "$ROLE" = "client" ]; then
    exec /usr/local/bin/interop-client
else
    exec /usr/local/bin/interop-server
fi
