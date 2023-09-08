#!/bin/bash
# Run kani verifier on the code

KANI_WEBSITE="https://model-checking.github.io/kani"

help_message() {
    echo "Run the Kani verifier on Mintlayer source"
    echo "Kani website / docs: $KANI_WEBSITE"
    echo
    echo "Verify the default basic properties:"
    echo "  $0 basic"
    echo
    echo "Try to verify everything, even potentially intractable properties:"
    echo "  $0 everything"
    echo
    echo "Anything after the command is passed through to kani"
}

COMMAND="$1"
shift

case "$COMMAND" in
    ""|"help") help_message; exit;;
    "basic") ARGS=("$@");;
    "everything") ARGS=(--features expensive-verification "$@");;
    *) echo "Unrecognized command: $COMMAND"; echo "Try $0 help"; exit 2;;
esac

# Sanity check to see Kani is installed
if ! cargo --list | grep kani >/dev/null; then
    echo "Kani not installed"
    echo "Please follow $KANI_WEBSITE/install-guide.html"
    exit 2
fi

# Let's avoid compiling everything with Kani, may be needlessly slow.
# Just list packages with verification here.
PKGS=(-p common)

# Kick it off
set -x
cargo kani "${PKGS[@]}" "${ARGS[@]}"
