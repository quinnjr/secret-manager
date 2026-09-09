#!/bin/sh
# Unprivileged half: build as the normal user, `sudo` only the install step,
# which is what docs/install-common.md tells the reader to do.
set -eu

# This script's `sudo make install` overwrites whatever secret-manager build
# is on the machine's install paths. See vagrant/guard.sh for why that is
# confined to the Vagrant box.
. "$(dirname "$0")/guard.sh"

cd "$HOME/secret-manager"

# The crate is edition 2024 and needs Rust >= 1.85. Debian 12's `rustc` is
# 1.63 and `rustup` is not packaged for bookworm at all, which is why the
# install doc says `rustc-web`/`cargo-web`. Check the version we actually
# got rather than trusting the package name.
if ! command -v cargo >/dev/null 2>&1; then
    echo "FAIL: no cargo on PATH after installing the documented packages" >&2
    exit 1
fi

echo "== toolchain =="
rustc --version
cargo --version

RUSTV="$(rustc --version | awk '{print $2}')"
MAJOR="${RUSTV%%.*}"; REST="${RUSTV#*.}"; MINOR="${REST%%.*}"
if [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 85 ]; then
    echo "FAIL: rustc $RUSTV is too old for edition 2024 (need >= 1.85)" >&2
    exit 1
fi
echo "rustc $RUSTV satisfies edition 2024 (>= 1.85)"

echo "== make =="
make

echo "== sudo make install =="
sudo make install

echo "== where things landed =="
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
missing=0
for p in /usr/bin/secret-manager /usr/bin/sm /usr/bin/sm-askpass \
         "/usr/lib/$MULTIARCH/security/pam_secret_manager.so" \
         /usr/lib/systemd/user/secret-manager.service \
         /usr/share/dbus-1/services/org.freedesktop.secrets.service; do
    if [ -e "$p" ]; then
        printf 'ok      %s\n' "$p"
    else
        printf 'MISSING %s\n' "$p"
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt 0 ]; then
    echo "FAIL: $missing documented install path(s) missing after sudo make install" >&2
    exit 1
fi
