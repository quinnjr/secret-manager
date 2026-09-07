# Installing on Arch Linux

## Build and install

```sh
sudo pacman -S --needed rust pinentry dbus openssh pam
make
sudo make install
```

`sudo make install` puts the binary at `/usr/bin/secret-manager` with the `sm`
and `sm-askpass` symlinks, the PAM module in `/usr/lib/security`, the systemd
user unit, the D-Bus activation file, an `environment.d` file for
`SSH_ASKPASS`, and shell completions.

See "Building" in `docs/install-common.md` for why you should build as your
normal user and only `sudo` the install step.

## Replace gnome-keyring or kwallet as the Secret Service

Only one service may own `org.freedesktop.secrets` on the session bus.

```sh
systemctl --user disable --now gnome-keyring-daemon.service gnome-keyring-daemon.socket 2>/dev/null
systemctl --user mask gnome-keyring-daemon.service
```

If `gnome-keyring` is installed, its own activation file also claims the bus
name. Override it for your user so the bus starts secret-manager instead:

```sh
mkdir -p ~/.local/share/dbus-1/services
cp /usr/share/dbus-1/services/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
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

Add the three lines from `/usr/share/doc/secret-manager/pam.d-snippet` to the
stacks you log in through. The `session` line must come after `pam_systemd.so`
so `/run/user/<uid>` exists:

| Login path        | File                      |
|-------------------|---------------------------|
| console           | `/etc/pam.d/login`        |
| SDDM              | `/etc/pam.d/sddm`         |
| GDM               | `/etc/pam.d/gdm-password` |
| LightDM           | `/etc/pam.d/lightdm`      |
| ssh               | `/etc/pam.d/sshd`         |
| `passwd` sync     | `/etc/pam.d/passwd`       |

Example for `/etc/pam.d/sddm`:

```
auth      include   system-login
auth      optional  pam_secret_manager.so
account   include   system-login
password  include   system-login
password  optional  pam_secret_manager.so
session   include   system-login
session   optional  pam_secret_manager.so
```

Log out and back in, then `sm status` should show `default` unlocked.
Problems are logged to the journal: `journalctl -p warning -g pam_secret_manager`
(the messages carry a `pam_secret_manager:` prefix in `authpriv`).

For creating your vault, SSH passphrases (including the
`SSH_ASKPASS_REQUIRE` opt-in and its risks), configuration, and
troubleshooting, see `docs/install-common.md`.

## Uninstalling

```sh
sudo make uninstall
```

`make uninstall` must repeat any `PREFIX` or `PAMDIR` override you passed to
`make install`, or it will look in the wrong place and leave files behind.
