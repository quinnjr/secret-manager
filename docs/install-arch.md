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

## Create your vault and start the daemon

```sh
sm init                       # creates the "default" collection
systemctl --user enable --now secret-manager.service
sm status
```

## Unlock at login (PAM)

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
