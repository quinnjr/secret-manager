# Installing on Debian

## Build and install

```sh
sudo apt install rustc-web cargo-web pinentry-curses pinentry-gnome3 dbus \
    openssh-client libpam0g-dev build-essential
make
sudo make install
```

**Why `rustc-web` and not `rustc`.** This crate is edition 2024 and needs
Rust 1.85 or newer. Debian 12's `rustc` is 1.63, and `rustup` is not packaged
for bookworm at all — `apt install rustup` there fails with "no installation
candidate". `rustc-web`/`cargo-web` are Debian's newer Rust, currently 1.96,
and they install as plain `/usr/bin/rustc` and `/usr/bin/cargo`, so nothing
else on this page changes. Verified on Debian 12.9; see `docs/vagrant.md`,
which checks these instructions on a real box.

On a Debian release that packages `rustup`, that works too, as does the
upstream toolchain from <https://rustup.rs>. Any Rust ≥ 1.85 is fine; the
package names are the only Debian-specific part.

`PAMDIR` defaults to `/usr/lib/<multiarch-triplet>/security` on Debian and
derivatives, auto-detected via `dpkg-architecture -qDEB_HOST_MULTIARCH`
(falling back to `/usr/lib/security` when that tool is unavailable). Override
it explicitly for cross builds or an unusual layout, e.g.:

```sh
sudo make install PAMDIR=/usr/lib/aarch64-linux-gnu/security
```

`sudo make install` puts the binary at `/usr/bin/secret-manager` with the `sm`
and `sm-askpass` symlinks, the PAM module in `$PAMDIR`, the systemd user unit,
the D-Bus activation file, an `environment.d` file for `SSH_ASKPASS`, and
shell completions.

See "Building" in `docs/install-common.md` for why you should build as your
normal user and only `sudo` the install step.

## Replace gnome-keyring or kwallet as the Secret Service

Only one service may own `org.freedesktop.secrets` on the session bus.

```sh
systemctl --user mask gnome-keyring-daemon.service
```

**Masking the unit also removes your PKCS#11 provider.** The packaged unit
runs `--components="pkcs11,secrets"` as one process, so stopping it stops
both. If you use certificates or a smartcard through NSS — Evolution,
Chrome, Firefox — re-enable that half alone through the autostart entry
below, and disable only `secrets`.

If `gnome-keyring` is installed, its own activation file also claims the bus
name. Override it for your user so the bus starts secret-manager instead:

```sh
mkdir -p ~/.local/share/dbus-1/services
cp /usr/share/dbus-1/services/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
```

**The systemd unit is not the only thing that starts it.**
`/etc/xdg/autostart/gnome-keyring-secrets.desktop` launches
`gnome-keyring-daemon --components=secrets` from a plain desktop session even
with the unit masked, and it will take the bus name before secret-manager
does. Shadow it with a per-user override — same filename, `Hidden=true`:

```sh
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/gnome-keyring-secrets.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=GNOME Keyring: Secret Service (disabled)
Exec=/usr/bin/gnome-keyring-daemon --start --foreground --components=secrets
Hidden=true
X-GNOME-Autostart-enabled=false
EOF
```

To keep PKCS#11 while disabling secrets, leave
`/etc/xdg/autostart/gnome-keyring-pkcs11.desktop` alone and do not write an
override for it.

Removing gnome-keyring entirely is simpler and handles the unit, the
activation file and both autostart entries at once:

```sh
sudo apt purge gnome-keyring
```

It also removes the PKCS#11 provider, with the consequences above, and APT
will pull in several GNOME packages as dependents — read what it proposes
before agreeing.

### KWallet

KWallet claims `org.freedesktop.secrets` through `ksecretd`, and it does so
at runtime — it will hold the name even when the system activation file
names gnome-keyring, so the `cp` above does not displace it. Turning it off
takes four steps, and none of them is the D-Bus override.

Disable the wallet subsystem:

```sh
kwriteconfig6 --file kwalletrc --group Wallet --key Enabled false
```

(System Settings › KDE Wallet is the same setting. `kwriteconfig5` on a
Plasma 5 system, which is what Debian stable ships. Without the key, the
default is enabled.)

Stop it being activated on demand, under both of its other names:

```sh
mkdir -p ~/.local/share/dbus-1/services
for n in org.kde.secretservicecompat org.freedesktop.impl.portal.desktop.kwallet; do
  printf '[D-BUS Service]\nName=%s\nExec=/bin/false\n' "$n" \
    > ~/.local/share/dbus-1/services/$n.service
done
```

The second name is the xdg-desktop-portal Secret backend: without it,
sandboxed and Flatpak applications keep reaching KWallet after you have taken
the main bus name.

If `pam_kwallet5` is in your login stack it will keep unlocking and starting
KWallet at every login, in parallel with secret-manager's own PAM module.
Find it:

```sh
grep -rn pam_kwallet /etc/pam.d/
```

Comment out the `auth` and `session` lines it matches — on a Debian KDE
install these are usually in `/etc/pam.d/sddm` and
`/etc/pam.d/sddm-autologin`. **Keep a root shell open on another TTY while
you test a new login** — a broken PAM stack can lock you out of the display
manager. These lines are prefixed `-`, so PAM already tolerates the module
being absent, which makes commenting them out the low-risk edit. They are
package-owned and may return on upgrade.

Finally, log out and back in. `ksecretd` holds the bus name for the life of
the session, so nothing short of a fresh session releases it. Then check:

```sh
busctl --user status org.freedesktop.secrets | grep -E 'Pid|Comm'
```

`Comm` should read `secret-manager`. If it still says `ksecretd`, one of the
four steps has not taken effect.

See `docs/install-common.md` (installed alongside this file at
`/usr/share/doc/secret-manager/install-common.md`) for creating your vault,
SSH passphrases, configuration, and troubleshooting — shared across
distributions.

## Unlock at login (PAM)

`tests/pam_stack.rs` drives this module through a real libpam stack in a
plain `cargo test`, so the entry points and the unlock itself are covered.
That suite runs as an ordinary user, so the root-only paths a real login
takes — the `/run/user/<uid>` socket, the `systemctl --machine` auto-start —
are not (see "Known gaps" in the README). Test login unlock on a spare
session before relying on it for your main login.

Add the three lines from `/usr/share/doc/secret-manager/pam.d-snippet` to
`common-auth`, `common-session`, and `common-password`. In `common-session`,
append the `session` line after the `pam_systemd.so` line so
`/run/user/<uid>` exists.

Debian's `pam-auth-update` will not manage these lines; edit the files
directly.

Example addition to `/etc/pam.d/common-auth`:

```
auth      optional  pam_secret_manager.so
```

Example addition to `/etc/pam.d/common-session` (after `pam_systemd.so`):

```
session   optional  pam_secret_manager.so
```

Example addition to `/etc/pam.d/common-password`:

```
password  optional  pam_secret_manager.so
```

Log out and back in, then `sm status` should show `default` unlocked.
Problems are logged to the journal: `journalctl -p warning -g pam_secret_manager`
(the messages carry a `pam_secret_manager:` prefix in `authpriv`).

For creating your vault, SSH passphrases (including the
`SSH_ASKPASS_REQUIRE` opt-in and its risks), configuration, and
troubleshooting, see `docs/install-common.md`.

## Uninstalling

```sh
sudo make uninstall PAMDIR=/usr/lib/aarch64-linux-gnu/security   # if you overrode PAMDIR at install
```

`make uninstall` must repeat any `PREFIX` or `PAMDIR` override you passed to
`make install` (the auto-detected default is reused automatically if you
didn't), or it will look in the wrong place and leave files behind.
