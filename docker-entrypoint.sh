#!/bin/sh
# Preserve other runtime settings while disabling implicit MPTCP listeners.
export GODEBUG="${GODEBUG:+${GODEBUG},}multipathtcp=0"
exec N2X "$@"
