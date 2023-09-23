#!/bin/sh

# DPRKeygen: a Red Star OS 3 Server Licence Key Extractor

# Dump all the memory process of a virtual machine from its PID, search for the
# Red Star OS 3 Server licence key and print it

# It works with QEMU/KVM. I have not tried it on any other virtual software, but
# it *should* work.

# This script is designed to work instantly as long as you provide the exact
# PID. I do not verify the input or watshoever.

if [ $# -ne 1 ]
then
    echo "Usage: $0 PID" >&2
    exit 1
fi

if [ $UID -ne 0 ]
then
    echo "You need to be root to read the mapped memory" >&2
    exit 2
fi

echo "Extracting memory (this may take some time)"
grep rw-p /proc/$1/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read start stop; do \
    gdb --batch --pid $1 -ex \
        "dump memory $1-$start-$stop.dump 0x$start 0x$stop" >/dev/null 2>&1 ; \
    interesting_file=$(grep -E '^([a-zA-Z0-9]{4}-){4}[a-zA-Z0-9]{4}$' *.dump 2>&1 | cut -d':' -f2 | sed 's/ //') ; \
    if [ -n "$interesting_file" ] ; then \
        echo "Searching for the licence key" ; \
        strings "$interesting_file" > "$interesting_file.strings" ; \
        echo -n "Licence Key is: " ; \
        grep -E '^([a-zA-Z0-9]{4}-){4}[a-zA-Z0-9]{4}$' "$interesting_file.strings" | cut -d':' -f3 ; \
        rm *.dump *.strings ; \
        exit 0; \
    else \
        rm *.dump ; \
    fi ; \
    done
