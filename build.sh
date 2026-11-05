#!/bin/bash
set -e
mkdir -p build
gcc -Wall -Wextra -O2 -Isrc -o build/securechannel \
    src/securechannel.c src/handshake.c \
    -lnetfilter_queue -lssl -lcrypto
echo "built build/securechannel"
