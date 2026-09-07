# Installing on Debian

## Build and install

```sh
sudo apt install rustup pinentry-curses pinentry-gnome3 dbus openssh-client libpam0g-dev build-essential
make
sudo make install
```

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

If `gnome-keyring` is installed, its own activation file also claims the bus
name. Override it for your user so the bus starts secret-manager instead:

```sh
mkdir -p ~/.local/share/dbus-1/services
cp /usr/share/dbus-1/services/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
```

The simplest alternative is to remove gnome-keyring entirely:

```sh
sudo apt purge gnome-keyring
```

KWallet does not claim `org.freedesktop.secrets` unless `kwallet-secrets`
(`ksecretd`) is enabled; disable that in System Settings › KDE Wallet.

See `docs/install-common.md` (installed alongside this file at
`/usr/share/doc/secret-manager/install-common.md`) for creating your vault,
SSH passphrases, configuration, and troubleshooting — shared across
distributions.

## Unlock at login (PAM)

This module's logic is unit-tested, but nothing drives it through a real
libpam stack automatically (see "Known gaps" in the README). Test login
unlock on a spare session before relying on it for your main login.

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
