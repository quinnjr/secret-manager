#!/bin/sh
# Root half of the provision: exactly the `apt install` line from
# docs/install-debian.md, plus what the *verification* needs (which the
# document rightly does not ask a user to install).
#
# If this script has to install something the document does not list, the
# document is wrong — say so here rather than quietly fixing it.
set -eu

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

echo "== the packages docs/install-debian.md tells the user to install =="
# Verbatim from the doc. Do not "improve" this list; its accuracy is the
# thing under test.
apt-get install -y -qq \
    rustc-web cargo-web pinentry-curses pinentry-gnome3 dbus openssh-client \
    libpam0g-dev build-essential

echo "== extra packages needed only to *verify*, not to install =="
# libsecret-tools gives `secret-tool`, which the test suite uses to prove
# libsecret interop. dbus-x11 gives `dbus-run-session` for a headless
# session bus. Neither belongs in the install doc.
apt-get install -y -qq libsecret-tools dbus-x11 pkg-config

echo "== what Debian actually ships =="
echo "debian:  $(cat /etc/debian_version)"
echo "rustup:  $(apt-cache policy rustup 2>/dev/null | awk '/Candidate/{print $2}' || echo '?')  (none on bookworm — why the doc says rustc-web)"
echo "rustc-web: $(dpkg-query -W -f='${Version}' rustc-web 2>/dev/null || echo 'not installed')"
echo "rustc:   $(dpkg-query -W -f='${Version}' rustc 2>/dev/null || echo 'not installed via apt')"
echo "multiarch: $(dpkg-architecture -qDEB_HOST_MULTIARCH)"
