#!/bin/sh
# Some simple custom code lints, mostly implemented by means of grepping code

# Find rust source files, check if there are matching lines
match_rs() {
    grep --extended-regexp --with-filename --line-number \
        --recursive --exclude-dir=.git --exclude-dir=target --include='*.rs' \
        "$@"
}

disallow_except_in() {
    echo "==== Checking code does not contain '$1' ===="
    match_rs --exclude-dir="$2" -e "$1"
    RET="$?"
    echo
    case "$RET" in
        0) return 1;;
        1) return 0;;
        *) return "$RET";;
    esac
}

FAIL=0

disallow_except_in 'parity_scale_codec' 'serialization' || FAIL=1
disallow_except_in 'jsonrpsee' 'rpc' || FAIL=1

exit $FAIL
