# Installing on Debian

## Build and install

```sh
sudo apt install rustup pinentry-curses pinentry-gnome3 dbus openssh-client libpam0g-dev build-essential
make
sudo make install PAMDIR=/usr/lib/x86_64-linux-gnu/security
```

(`dpkg-architecture -qDEB_HOST_MULTIARCH` gives the correct triplet on other
architectures, e.g. `aarch64-linux-gnu`.)

`sudo make install` puts the binary at `/usr/bin/secret-manager` with the `sm`
and `sm-askpass` symlinks, the PAM module in `$PAMDIR`, the systemd user unit,
the D-Bus activation file, an `environment.d` file for `SSH_ASKPASS`, and
shell completions.

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

## Create your vault and start the daemon

```sh
sm init                       # creates the "default" collection
systemctl --user enable --now secret-manager.service
sm status
```

## Unlock at login (PAM)

This module is exercised end to end by an integration test only on
machines with `libpam-wrapper` and its `pam_matrix` test module installed
(`sudo apt install libpam-wrapper`); it has not been run on the development
machine. Test login unlock on a spare session before relying on it for
your main login.

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

## SSH passphrases

```sh
sm ssh add ~/.ssh/id_ed25519          # prompts for the key's passphrase once
sm ssh add ~/.ssh/id_deploy --no-passphrase
sm ssh list
```

The installed `environment.d` file sets `SSH_ASKPASS=/usr/bin/sm-askpass` and
`SSH_ASKPASS_REQUIRE=prefer` for systemd user sessions. Shells started outside
a systemd session (for example a plain `startx`) need the same two variables
exported in your profile.

## Configuration

`~/.config/secret-manager/config.toml`, all keys optional:

```toml
[vault]
dir = "~/.local/share/secret-manager"
auto_lock_after = "0s"      # "15m" locks after 15 minutes of inactivity

[prompt]
pinentry = "pinentry"       # e.g. "/usr/bin/pinentry-qt"

[kdf]
m_cost_kib = 65536
t_cost = 3
p_cost = 1
```
