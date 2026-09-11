#!/bin/sh
# Shared VM guard, sourced by both build.sh and verify.sh: both run
# `sudo make install` (and verify.sh also `sudo make uninstall`) against
# whatever `secret-manager` checkout happens to be at $HOME/secret-manager.
# That is fine inside the Vagrant box the Vagrantfile names
# "secret-manager-debian" and nowhere else — run either script on a
# developer's own machine and it installs, or uninstalls and reinstalls,
# their live secret-manager from an arbitrary build. Refuse outside the box.
if [ "$(hostname)" != "secret-manager-debian" ]; then
    echo "FAIL    refusing to run outside the secret-manager-debian Vagrant box" >&2
    echo "        (hostname is '$(hostname)'; this script installs, or" >&2
    echo "        uninstalls and reinstalls, secret-manager and must not" >&2
    echo "        touch a real machine)" >&2
    exit 1
fi
