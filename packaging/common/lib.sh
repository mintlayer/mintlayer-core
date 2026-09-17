#!/usr/bin/env bash
# Shared helpers for the packaging builders (deb, rpm, arch) and smoke tests.
# Sourced, not executed. Pure bash, no external tools required except where a
# function documents them; all container images used by the builders provide
# what the functions need (the builders self-provision help2man and gzip).

# The CLI daemons and tools shipped by the mintlayer-node package, in every
# package format. The GUI binary (node-gui) is handled separately by each
# builder. Note: the Windows installers and the workflow binary_list defaults
# duplicate this list outside the shell world (NSIS/PowerShell/YAML cannot
# source bash) — keep them in sync when a binary is added.
NODE_BINARIES=(
    node-daemon
    wallet-rpc-daemon
    api-web-server
    api-blockchain-scanner-daemon
    dns-server
    wallet-cli
    wallet-address-generator
)

# Validate a release version string (X.Y.Z with an optional -suffix).
# Sets VERSION_FORMAT_ERROR to a human-readable message and returns 1 when
# invalid.
# Note: the character class uses a POSIX class — explicit ranges like `+-a`
# in a glob bracket expression are parsed counter-intuitively and reject
# letters.
# Note: '~' and '+' are rejected on purpose: the rpm builder maps '-' to '~'
# and the Arch builder maps '-' to '_', and both mappings must stay injective
# so that distinct versions cannot produce the same package version.
validate_version() {
    local version="$1"
    if [ -z "$version" ] || [[ "$version" == *[![:alnum:].-]* ]]; then
        VERSION_FORMAT_ERROR="invalid version: $version"
        return 1
    fi
    case "$version" in
        [0-9]*.[0-9]*.[0-9]*) ;;  # e.g. 1.4.1, 1.4.1-rc1
        *)
            VERSION_FORMAT_ERROR="invalid version (expected X.Y.Z[-suffix]): $version"
            return 1
            ;;
    esac
}

# Generate gzip-compressed man pages (from --help output) for every binary in
# <bin-dir> into <bin-dir-man-man1>. Requires help2man and gzip (installed by
# every builder's self-provisioning step).
#   gen_man <bin-dir> <version> <runnable: 1|0>
# runnable=0 ships stub pages (cross-target builds cannot execute the
# binaries).
gen_man() {
    local bin_dir="$1"
    local version="$2"
    local runnable="$3"

    export LC_ALL=C.UTF-8
    local man_dir="$bin_dir/usr/share/man/man1"
    mkdir -p "$man_dir"
    local binpath binname
    for binpath in "$bin_dir"/usr/bin/*; do
        binname="$(basename "$binpath")"
        if [ "$runnable" -eq 1 ] && "$binpath" --help >/dev/null 2>&1; then
            help2man --no-info --version-string="$version" \
                --name="Part of the Mintlayer node software" \
                "$binpath" > "$man_dir/$binname.1" 2>/dev/null ||
                { echo "warning: help2man failed for $binname, shipping stub" >&2
                  printf '.TH %s 1\n.SH NAME\n%s \\- Mintlayer tool\n' "$binname" "$binname" \
                    > "$man_dir/$binname.1"; }
        else
            echo "warning: $binname --help not runnable, shipping stub man page" >&2
            printf '.TH %s 1\n.SH NAME\n%s \\- Mintlayer tool\n' "$binname" "$binname" \
                > "$man_dir/$binname.1"
        fi
        gzip -n -9 "$man_dir/$binname.1"
    done
}
