#!/bin/sh

[ "${GOINSTALL:+defined}" ] || {
    # No gp packages to install. Do nothing.
    exit 0
}

# -----------------------------------------------------------------------------
# Install go packages
# -----------------------------------------------------------------------------

# shellcheck disable=SC2086
for pkg in $GOINSTALL
do
    go install "$pkg"
done
