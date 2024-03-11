#!/bin/bash

set -eu

ML_USER_ID=${ML_USER_ID:-10001}
ML_GROUP_ID=${ML_GROUP_ID:-10001}

# Create a group and a user; but first check if they already exist (in case an existing
# container is re-used).
if [[ ! $(id -g mintlayer 2> /dev/null) ]]; then
    groupadd -g "$ML_GROUP_ID" mintlayer
fi
if [[ ! $(id -u mintlayer 2> /dev/null) ]]; then
    # Note: /home/mintlayer should already be mounted to a host directory (or a volume),
    # so it must exist.
    useradd -u "$ML_USER_ID" -g mintlayer -d /home/mintlayer --no-create-home mintlayer
fi

# Change the owner of /home/mintlayer (and therefore the host directory where it's mounted).
chown mintlayer:mintlayer /home/mintlayer

# Launch the passed program using the "mintlayer" user.
# Note:
# 1) 'exec' will replace the current shell process with the specified program; this is needed
# for signals to be propagated corectly.
# 2) 'gosu' also uses the 'exec' syscall to launch the program (unlike 'su') and is needed
# for the same reason.
exec gosu mintlayer "$@"
