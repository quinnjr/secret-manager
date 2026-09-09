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

**Move your secrets across before you turn the old one off.** Disabling a
provider does not migrate anything, and the steps below leave the old files
in place but unread. `sm import --from gnome-keyring --inventory` prints
what is in the source from its cleartext headers alone — no password, no
daemon — and `sm import --from gnome-keyring --dry-run` runs the whole
extraction and every check and writes nothing. Both report, per item,
whether the application that wrote it will still find it; see "Commands" in
`README.md` for what the three outcomes mean, and use `--from kwallet` for
the KWallet section below.

```sh
systemctl --user disable --now gnome-keyring-daemon.service gnome-keyring-daemon.socket 2>/dev/null
systemctl --user mask gnome-keyring-daemon.service
```

**Masking the unit also removes your PKCS#11 provider.** The packaged unit
runs `--components="pkcs11,secrets"` as one process, so stopping it stops
both. If you use certificates or a smartcard through NSS — Evolution,
Chrome, Firefox — re-enable that half alone, through the autostart entry
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
does. Shadow it with a per-user override — same filename, `Hidden=true`.
This truncates any override already at this path — check first if you have
one:

```sh
mkdir -p ~/.config/autostart
if [ -e ~/.config/autostart/gnome-keyring-secrets.desktop ]; then
    echo "~/.config/autostart/gnome-keyring-secrets.desktop already exists;" >&2
    echo "not overwriting — edit it by hand to add Hidden=true instead." >&2
else
    cat > ~/.config/autostart/gnome-keyring-secrets.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=GNOME Keyring: Secret Service (disabled)
Exec=/usr/bin/gnome-keyring-daemon --start --foreground --components=secrets
Hidden=true
X-GNOME-Autostart-enabled=false
EOF
fi
```

To keep PKCS#11 while disabling secrets, leave
`/etc/xdg/autostart/gnome-keyring-pkcs11.desktop` alone and do not write an
override for it.

### KWallet

This section — `ksecretd`'s behaviour, the file paths, the PAM stack
contents — was reasoned from Arch's packaging, not checked on a live KDE
session.

Import the wallet before disabling it: `sm import --from kwallet --dry-run`
(see "Commands" in `README.md`). A native KWallet entry has no attributes,
so it is preserved and findable with `sm list` and `sm get`, but no
libsecret client that did not write it will look it up — the dry run says
how many of yours are in that case.

KWallet claims `org.freedesktop.secrets` through `ksecretd`, and it does so
at runtime — it will hold the name even when the system activation file
names gnome-keyring, so the `cp` above does not displace it. Turning it off
takes four steps, and none of them is the D-Bus override.

Disable the wallet subsystem:

```sh
kwriteconfig6 --file kwalletrc --group Wallet --key Enabled false
```

(System Settings › KDE Wallet is the same setting. `kwriteconfig5` on a
Plasma 5 system. Without the key, the default is enabled.)

Stop it being activated on demand, under both of its other names. This
truncates any override already at these paths — check first if you have one:

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
KWallet at every login, in parallel with secret-manager's own PAM module. On
Arch it appears in `/etc/pam.d/sddm`, `/etc/pam.d/sddm-autologin` and
`/etc/pam.d/wdm`:

```sh
grep -rn pam_kwallet /etc/pam.d/
```

Comment out the `auth` and `session` lines it matches. **Keep a root shell
open on another TTY while you test a new login** — a broken PAM stack can
lock you out of the display manager. These lines are prefixed `-`, so PAM
already tolerates the module being absent, which makes commenting them out
the low-risk edit. They are package-owned and may return on upgrade.

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
