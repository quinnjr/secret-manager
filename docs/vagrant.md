# Verifying the Debian instructions

`docs/install-debian.md` was written from Debian's packaging and from
reasoning about it, on an Arch machine. This directory's Vagrant setup exists
so those instructions are *checked* rather than believed, on a real Debian
box with no desktop, no gnome-keyring and no kwallet — the configuration a
reader is least likely to have tested for us.

It earned its keep on the first run: `apt install rustup`, which the document
told every Debian user to run, fails on Debian 12 with "Package 'rustup' has
no installation candidate". See "What it found" below.

```sh
make vagrant-verify      # boot, install, verify; non-zero if anything fails
make vagrant-clean       # destroy the box

vagrant provision --provision-with verify   # re-run only the checks
vagrant ssh                                 # poke at a working install
```

Needs `vagrant` and a provider; the `Vagrantfile` is written for VirtualBox
and asks for 4 CPUs and 4 GiB, which a release build wants.

## What it does

Three provisioners, matching the three things a reader does:

`vagrant/provision.sh` runs **the `apt install` line from the install document
verbatim**. Do not "improve" that list — its accuracy is the thing under test.
It then installs the few extras the *verification* needs and the document
rightly does not ask for: `libsecret-tools` for `secret-tool`, and `dbus-x11`
for `dbus-run-session`.

`vagrant/build.sh` builds as the normal user and `sudo`s only the install
step, as `docs/install-common.md` instructs, then checks the toolchain is
actually new enough rather than trusting the package name, and reports where
every installed file landed.

`vagrant/verify.sh` proves the result works:

- the `sm` and `sm-askpass` argv0 aliases really are symlinks to the one
  binary;
- the PAM module is at the multiarch path the document promises, exports
  `pam_sm_open_session`, and **does not link tokio or zbus** — the invariant
  `CLAUDE.md` states, checked here against an installed artifact rather than
  a build flag;
- a daemon on a private session bus, a vault, a secret stored and read back,
  `secret-tool` interop in *both* directions, and `sm lock`;
- `sm import --inventory` runs with no source and no daemon;
- the docs the install step promises are installed;
- `make uninstall` removes what `make install` placed, then reinstalls so
  `vagrant ssh` leaves a working box.

Every check prints `ok` or `FAIL` and the script exits non-zero if any
failed, so `vagrant up` is itself the test run.

The box gets a private network and no forwarded ports beyond SSH: the daemon
is a session-bus service and nothing here should be reachable from outside
the VM. The synced folder is rsync with `target/` excluded — the box has no
guest additions, and host build artifacts are for a different toolchain.

## What it found

**Debian 12 cannot follow the documented install line.** The document said
`sudo apt install rustup …`. On Debian 12.9:

- `rustup` has no installation candidate at all — it is not packaged for
  bookworm, in main or in backports.
- `rustc` is 1.63.0, and this crate is edition 2024, which needs 1.85 or
  newer. So the obvious substitution does not work either.
- `rustc-web` and `cargo-web` are Debian's newer Rust — 1.96.0 on 12.9 — and
  they install as plain `/usr/bin/rustc` and `/usr/bin/cargo`, so nothing
  else on the page changes.

The document now says `rustc-web cargo-web`, and explains why, because the
substitution is not obvious and a reader hitting "no installation candidate"
has no way to guess it.

Everything else on the page was correct as written, including the multiarch
`PAMDIR` detection via `dpkg-architecture -qDEB_HOST_MULTIARCH`, which
resolved to `/usr/lib/x86_64-linux-gnu/security`.

## Scope

This verifies the *install document*, not the test suite — `cargo test`
belongs on the development machine, where it runs in seconds against a
debug build. Nor does it verify the KWallet or gnome-keyring
decommissioning steps, which need a desktop session; those remain reasoned
rather than checked, and the migration spec
(`docs/superpowers/specs/2026-09-08-migration-assistant.md`) says so.

Arch is the development machine and is exercised continuously; there is no
Arch box here for that reason.
