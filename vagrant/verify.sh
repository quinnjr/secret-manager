#!/bin/sh
# Prove the installed thing works, on a headless Debian box with no desktop,
# no gnome-keyring and no kwallet — the case the install doc's readers are
# least likely to have tested for us.
#
# Every check prints ok/FAIL and the script exits non-zero if any failed, so
# `vagrant up` is itself the test run.
set -u
cd "$HOME/secret-manager"
export PATH="$HOME/.cargo/bin:$PATH"

fails=0
ok()   { printf 'ok      %s\n' "$1"; }
fail() { printf 'FAIL    %s\n' "$1"; fails=$((fails + 1)); }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else fail "$1"; fi; }

echo "== the binary and its argv0 aliases =="
check "secret-manager --version"       "secret-manager --version"
check "sm is the same binary"          "[ \"\$(readlink /usr/bin/sm)\" = secret-manager ]"
check "sm-askpass is the same binary"  "[ \"\$(readlink /usr/bin/sm-askpass)\" = secret-manager ]"

echo "== the PAM module is a real PAM module =="
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
PAMSO="/usr/lib/$MULTIARCH/security/pam_secret_manager.so"
check "PAM module at the documented multiarch path" "[ -f '$PAMSO' ]"
check "PAM module exports pam_sm_open_session" \
      "nm -D --defined-only '$PAMSO' | grep -q pam_sm_open_session"
check "PAM module does not link tokio/zbus" \
      "! nm -D '$PAMSO' 2>/dev/null | grep -qiE 'tokio|zbus'"

echo "== a real session, a real vault, a real secret =="
# dbus-run-session gives a private session bus with no desktop. The daemon
# is started by hand rather than by systemd --user, which is not running in
# a `vagrant ssh` context.
cat > /tmp/session-test.sh <<'INNER'
set -eu
export PATH="$HOME/.cargo/bin:$PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/rt-$$}"
mkdir -p "$XDG_RUNTIME_DIR" && chmod 700 "$XDG_RUNTIME_DIR"
export XDG_DATA_HOME="$HOME/.local/share"

# A scripted pinentry so nothing needs a terminal or a display.
mkdir -p "$HOME/bin"
cat > "$HOME/bin/fake-pinentry" <<'PIN'
#!/bin/sh
echo "OK Pleased to meet you"
while read -r line; do
  case "$line" in
    GETPIN) printf 'D vagrant-test-passphrase\nOK\n' ;;
    BYE)    echo "OK closing connection"; exit 0 ;;
    *)      echo OK ;;
  esac
done
PIN
chmod +x "$HOME/bin/fake-pinentry"
mkdir -p "$HOME/.config/secret-manager"
printf '[prompt]\npinentry = "%s/bin/fake-pinentry"\n' "$HOME" \
  > "$HOME/.config/secret-manager/config.toml"

printf 'vagrant-test-passphrase\n' | sm init >/dev/null
secret-manager daemon & DAEMON=$!
trap 'kill $DAEMON 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  busctl --user status org.freedesktop.secrets >/dev/null 2>&1 && break
  sleep 0.2
done

printf 'hunter2' | sm set app=vagrant user=tester --label "Vagrant probe"
got="$(sm get app=vagrant user=tester)"
[ "$got" = "hunter2" ] || { echo "sm round trip: got '$got'"; exit 1; }

# The point of the whole project: a libsecret client must see it.
st="$(secret-tool lookup app vagrant user tester)"
[ "$st" = "hunter2" ] || { echo "secret-tool lookup: got '$st'"; exit 1; }

# And the reverse direction.
printf 'from-secret-tool' | secret-tool store --label='ST probe' k v
back="$(sm get k=v)"
[ "$back" = "from-secret-tool" ] || { echo "reverse interop: got '$back'"; exit 1; }

sm list >/dev/null
sm status >/dev/null
sm lock
sm status | grep -qi lock

echo "INNER-OK"
INNER
chmod +x /tmp/session-test.sh

out="$(dbus-run-session -- sh /tmp/session-test.sh 2>&1)"
if printf '%s' "$out" | grep -q INNER-OK; then
    ok "daemon, vault, sm round trip, secret-tool interop both ways, lock"
else
    fail "session test"
    printf '%s\n' "$out" | sed 's/^/        /'
fi

echo "== sm import, which needs neither a source nor a daemon =="
check "sm import --help"                 "sm import --help"
check "sm import --inventory with no gnome-keyring reports absence, does not crash" \
      "sm import --from gnome-keyring --inventory; [ \$? -le 1 ]"

echo "== the docs the install step promises are installed =="
for d in install-arch.md install-debian.md install-common.md pam.d-snippet; do
    check "/usr/share/doc/secret-manager/$d" "[ -f /usr/share/doc/secret-manager/$d ]"
done

echo "== uninstall removes what it installed =="
sudo make uninstall >/dev/null 2>&1
check "binary gone after uninstall"      "[ ! -e /usr/bin/secret-manager ]"
check "sm symlink gone after uninstall"  "[ ! -e /usr/bin/sm ]"
check "PAM module gone after uninstall"  "[ ! -e '$PAMSO' ]"
# Reinstall so `vagrant ssh` leaves a working box to poke at.
sudo make install >/dev/null 2>&1

echo
if [ "$fails" -eq 0 ]; then
    echo "ALL CHECKS PASSED — docs/install-debian.md works on $(cat /etc/debian_version)"
else
    echo "$fails CHECK(S) FAILED"
fi
exit "$fails"
