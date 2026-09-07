//! Sanity checks on the shipped unit, activation, and Makefile install list.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn unit_and_activation_files_agree() {
    let unit = std::fs::read_to_string(root().join("dist/secret-manager.service")).unwrap();
    assert!(unit.contains("Type=dbus"));
    assert!(unit.contains("BusName=org.freedesktop.secrets"));
    assert!(unit.contains("ExecStart=/usr/bin/secret-manager daemon --foreground"));
    assert!(unit.contains("Conflicts=gnome-keyring-daemon.service"));
    assert!(unit.contains("StartLimitIntervalSec=60"));
    assert!(unit.contains("StartLimitBurst=5"));
    // Memory-exposure hardening.
    assert!(unit.contains("LimitCORE=0"));
    assert!(unit.contains("PrivateTmp=yes"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=full"));
    assert!(unit.contains("RuntimeDirectory=secret-manager"));
    assert!(unit.contains("RuntimeDirectoryMode=0700"));
    assert!(unit.contains("ProtectKernelTunables=yes"));
    assert!(unit.contains("RestrictSUIDSGID=yes"));
    assert!(unit.contains("ProtectKernelModules=yes"));
    assert!(unit.contains("ProtectKernelLogs=yes"));
    assert!(unit.contains("ProtectControlGroups=yes"));
    assert!(unit.contains("ProtectClock=yes"));
    assert!(unit.contains("ProtectHostname=yes"));
    assert!(unit.contains("RestrictNamespaces=yes"));
    assert!(unit.contains("RestrictRealtime=yes"));
    assert!(unit.contains("LockPersonality=yes"));
    assert!(unit.contains("CapabilityBoundingSet="));
    assert!(unit.contains("SystemCallFilter=@system-service"));
    assert!(unit.contains("SystemCallErrorNumber=EPERM"));
    assert!(!unit.contains("ReadWritePaths"));
    assert!(unit.contains("RestrictAddressFamilies=AF_UNIX AF_NETLINK"));
    assert!(!unit.contains("PrivateNetwork"));
    assert!(!unit.contains("MemoryDenyWriteExecute"));
    assert!(!unit.contains("PrivateDevices"));
    assert!(unit.contains("UMask=0077"));
    assert!(unit.contains("MemoryMax=1G"));
    assert!(unit.contains("SystemCallArchitectures=native"));
    // Comment block distinguishing load-bearing directives from defence in
    // depth on a user unit.
    assert!(unit.contains("load-bearing for"));
    assert!(unit.contains("defence in depth"));
    let activation =
        std::fs::read_to_string(root().join("dist/org.freedesktop.secrets.service")).unwrap();
    assert!(activation.contains("Name=org.freedesktop.secrets"));
    assert!(activation.contains("SystemdService=secret-manager.service"));
    let env =
        std::fs::read_to_string(root().join("dist/environment.d/50-secret-manager.conf")).unwrap();
    assert!(env.contains("SSH_ASKPASS=/usr/bin/sm-askpass"));
    // A terminal must still prompt interactively; this line would silently
    // satisfy SSH_ASKPASS from any terminal session too.
    assert!(!env.contains("SSH_ASKPASS_REQUIRE"));
}

/// The pam build must use its own `CARGO_TARGET_DIR` so it can never share
/// `target/release/libsecret_manager.so` with the default (daemon/CLI)
/// build, and `PAMSO` must default to that isolated path.
#[test]
fn makefile_isolates_the_pam_build_target_dir() {
    let makefile = std::fs::read_to_string(root().join("Makefile")).unwrap();
    assert!(
        makefile.contains("CARGO_TARGET_DIR=target/pam"),
        "pam build must set its own CARGO_TARGET_DIR"
    );
    assert!(
        makefile.contains("PAMSO   ?= target/pam/release/libsecret_manager.so"),
        "PAMSO must default into the isolated pam target dir"
    );
}

#[test]
fn make_install_dry_run_lists_every_artifact() {
    let out = std::process::Command::new("make")
        .args(["-n", "install", "DESTDIR=/tmp/sm-dry", "CARGO=true"])
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "/tmp/sm-dry/usr/bin/secret-manager",
        "sm-askpass",
        "pam_secret_manager.so",
        "systemd/user/secret-manager.service",
        "dbus-1/services/org.freedesktop.secrets.service",
        "environment.d/50-secret-manager.conf",
        "bash-completion/completions/sm",
        "zsh/site-functions/_sm",
        "fish/vendor_completions.d/sm.fish",
        "pam.d-snippet",
        "install-arch.md",
        "install-debian.md",
        "install-common.md",
    ] {
        assert!(text.contains(needle), "missing {needle} in:\n{text}");
    }
}

#[test]
fn make_uninstall_dry_run_lists_every_artifact() {
    let out = std::process::Command::new("make")
        .args(["-n", "uninstall", "DESTDIR=/tmp/sm-dry"])
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "systemctl",
        "/tmp/sm-dry/usr/bin/secret-manager",
        "sm-askpass",
        "pam_secret_manager.so",
        "systemd/user/secret-manager.service",
        "dbus-1/services/org.freedesktop.secrets.service",
        "environment.d/50-secret-manager.conf",
        "share/doc/secret-manager",
        "bash-completion/completions/sm",
        "zsh/site-functions/_sm",
        "fish/vendor_completions.d/sm.fish",
    ] {
        assert!(text.contains(needle), "missing {needle} in:\n{text}");
    }
}

#[test]
fn make_install_templates_prefix_into_shipped_files() {
    let out = std::process::Command::new("make")
        .args([
            "-n",
            "install",
            "PREFIX=/opt/sm",
            "DESTDIR=/tmp/sm-dry",
            "CARGO=true",
        ])
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("sed") && text.contains("/opt/sm/bin/"),
        "expected a sed rewrite to /opt/sm/bin/ in:\n{text}"
    );
}

#[test]
fn both_install_guides_reference_the_common_doc() {
    for guide in ["docs/install-arch.md", "docs/install-debian.md"] {
        let text = std::fs::read_to_string(root().join(guide)).unwrap();
        assert!(
            text.contains("install-common.md"),
            "{guide} does not reference install-common.md"
        );
    }
}

/// Build a tiny real shared object exporting a defined `pam_sm_open_session`
/// dynamic symbol, so the install guard (which greps `nm -D` output for that
/// symbol) accepts it as a genuine PAM build. Requires `cc` on `PATH`.
fn build_stub_pam_so(dir: &std::path::Path) -> PathBuf {
    let src = dir.join("stub_pam.c");
    let so = dir.join("stub-libpam_secret_manager.so");
    std::fs::write(
        &src,
        "int pam_sm_open_session(void) { return 0; }\n\
         int pam_sm_authenticate(void) { return 0; }\n",
    )
    .unwrap();
    let out = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "failed to build stub pam .so:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    so
}

/// Real (non-dry-run) install into a staging dir, using stub binaries so the
/// test does not need a release build, then a matching uninstall with
/// `systemctl` absent from `PATH` (as on a minimal build box).
#[test]
fn make_install_round_trips_into_a_staging_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let stage = tmp.path().join("stage");
    let bin = tmp.path().join("stub-secret-manager");
    let completions = tmp.path().join("completions");

    // `install` no longer executes $(BIN) (root must not run a user-built
    // binary); completion files are expected to already exist, as `build`
    // would have generated them. Simulate that here.
    std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let pamso = build_stub_pam_so(tmp.path());
    std::fs::create_dir_all(&completions).unwrap();
    std::fs::write(completions.join("sm"), "# fake bash completion\n").unwrap();
    std::fs::write(completions.join("_sm"), "# fake zsh completion\n").unwrap();
    std::fs::write(completions.join("sm.fish"), "# fake fish completion\n").unwrap();

    let install = std::process::Command::new("make")
        .args(["install"])
        .arg(format!("DESTDIR={}", stage.display()))
        .arg(format!("BIN={}", bin.display()))
        .arg(format!("PAMSO={}", pamso.display()))
        .arg("PAMDIR=/usr/lib/security")
        .arg(format!("COMPLETIONS_DIR={}", completions.display()))
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "install failed:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );

    let installed = [
        "usr/bin/secret-manager",
        "usr/bin/sm",
        "usr/bin/sm-askpass",
        "usr/lib/security/pam_secret_manager.so",
        "usr/lib/systemd/user/secret-manager.service",
        "usr/share/dbus-1/services/org.freedesktop.secrets.service",
        "usr/lib/environment.d/50-secret-manager.conf",
        "usr/share/doc/secret-manager/pam.d-snippet",
        "usr/share/doc/secret-manager/install-arch.md",
        "usr/share/doc/secret-manager/install-debian.md",
        "usr/share/doc/secret-manager/install-common.md",
        "usr/share/bash-completion/completions/sm",
        "usr/share/zsh/site-functions/_sm",
        "usr/share/fish/vendor_completions.d/sm.fish",
    ];
    for rel in installed {
        let p = stage.join(rel);
        assert!(p.exists(), "expected {rel} to exist after install");
    }
    // Symlinks point at the real binary name, not a copy.
    for link in ["usr/bin/sm", "usr/bin/sm-askpass"] {
        let p = stage.join(link);
        let target = std::fs::read_link(&p).unwrap();
        assert_eq!(target, PathBuf::from("secret-manager"));
    }
    let bin_mode = std::fs::metadata(stage.join("usr/bin/secret-manager"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(bin_mode, 0o755);
    // PAM modules are dlopened, never executed: 0644, not 0755.
    let pamso_mode = std::fs::metadata(stage.join("usr/lib/security/pam_secret_manager.so"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        pamso_mode, 0o644,
        "PAM module must be installed 0644, not executable"
    );
    // PREFIX was not overridden, so the shipped /usr/bin/ literal survives untouched.
    let unit =
        std::fs::read_to_string(stage.join("usr/lib/systemd/user/secret-manager.service")).unwrap();
    assert!(unit.contains("ExecStart=/usr/bin/secret-manager daemon --foreground"));

    // Uninstall with systemctl unavailable (best-effort disable must not fail the run).
    // The recipe needs `rm` and `readlink` (for the symlink-safety check), so
    // build a minimal PATH containing just those (found via the real PATH)
    // and nothing named `systemctl`; resolve `make` to an absolute path first
    // since Command looks it up in the PATH we are about to override.
    let which = |name: &str| -> PathBuf {
        let out = std::process::Command::new("sh")
            .args(["-c", &format!("command -v {name}")])
            .output()
            .unwrap();
        assert!(out.status.success(), "could not locate {name} on PATH");
        PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
    };
    let make_bin = which("make");
    let rm_bin = which("rm");
    let readlink_bin = which("readlink");
    let stub_path = tmp.path().join("stub-path");
    std::fs::create_dir_all(&stub_path).unwrap();
    std::os::unix::fs::symlink(&rm_bin, stub_path.join("rm")).unwrap();
    std::os::unix::fs::symlink(&readlink_bin, stub_path.join("readlink")).unwrap();

    let uninstall = std::process::Command::new(&make_bin)
        .args(["uninstall"])
        .arg(format!("DESTDIR={}", stage.display()))
        .arg("PAMDIR=/usr/lib/security")
        .env("PATH", &stub_path)
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        uninstall.status.success(),
        "uninstall failed:\n{}",
        String::from_utf8_lossy(&uninstall.stderr)
    );

    for rel in installed {
        let p = stage.join(rel);
        assert!(!p.exists(), "expected {rel} to be removed after uninstall");
    }
    assert!(!stage.join("usr/share/doc/secret-manager").exists());
}

/// `install` must refuse a `PAMSO` that isn't a real PAM build (no
/// `pam_sm_open_session` dynamic symbol), rather than silently shipping it
/// into the PAM directory.
#[test]
fn make_install_refuses_a_non_pam_build() {
    let tmp = tempfile::tempdir().unwrap();
    let stage = tmp.path().join("stage");
    let bin = tmp.path().join("stub-secret-manager");
    let completions = tmp.path().join("completions");
    let bad_pamso = tmp.path().join("not-a-pam-module.so");

    std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A daemon-flavoured (or just plain wrong) .so: no pam_sm_* symbols.
    std::fs::write(&bad_pamso, b"not an elf, not a pam module\n").unwrap();
    std::fs::create_dir_all(&completions).unwrap();
    std::fs::write(completions.join("sm"), "# fake bash completion\n").unwrap();
    std::fs::write(completions.join("_sm"), "# fake zsh completion\n").unwrap();
    std::fs::write(completions.join("sm.fish"), "# fake fish completion\n").unwrap();

    let install = std::process::Command::new("make")
        .args(["install"])
        .arg(format!("DESTDIR={}", stage.display()))
        .arg(format!("BIN={}", bin.display()))
        .arg(format!("PAMSO={}", bad_pamso.display()))
        .arg("PAMDIR=/usr/lib/security")
        .arg(format!("COMPLETIONS_DIR={}", completions.display()))
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        !install.status.success(),
        "install must fail when PAMSO is not a real PAM build"
    );
    let stderr = String::from_utf8_lossy(&install.stderr);
    assert!(
        stderr.contains("is not the PAM build"),
        "expected the guard's refusal message, got:\n{stderr}"
    );
    assert!(
        !stage
            .join("usr/lib/security/pam_secret_manager.so")
            .exists(),
        "the bad module must not have been installed"
    );
}

/// `install` must not clobber a `sm`/`sm-askpass` name that belongs to some
/// other package, and `uninstall` must not remove one it did not create.
#[test]
fn install_and_uninstall_protect_foreign_sm_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let stage = tmp.path().join("stage");
    let bin = tmp.path().join("stub-secret-manager");
    let completions = tmp.path().join("completions");
    let pamso = build_stub_pam_so(tmp.path());

    std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::create_dir_all(&completions).unwrap();
    std::fs::write(completions.join("sm"), "# fake bash completion\n").unwrap();
    std::fs::write(completions.join("_sm"), "# fake zsh completion\n").unwrap();
    std::fs::write(completions.join("sm.fish"), "# fake fish completion\n").unwrap();

    // Pre-populate the target bindir with a `sm` that belongs to some other
    // package (a real file, not a symlink to secret-manager).
    let bindir = stage.join("usr/bin");
    std::fs::create_dir_all(&bindir).unwrap();
    std::fs::write(bindir.join("sm"), "#!/bin/sh\necho not secret-manager\n").unwrap();
    std::fs::set_permissions(bindir.join("sm"), std::fs::Permissions::from_mode(0o755)).unwrap();

    let install = std::process::Command::new("make")
        .args(["install"])
        .arg(format!("DESTDIR={}", stage.display()))
        .arg(format!("BIN={}", bin.display()))
        .arg(format!("PAMSO={}", pamso.display()))
        .arg("PAMDIR=/usr/lib/security")
        .arg(format!("COMPLETIONS_DIR={}", completions.display()))
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        !install.status.success(),
        "install must refuse to overwrite a foreign sm"
    );
    let stderr = String::from_utf8_lossy(&install.stderr);
    assert!(
        stderr.contains("refusing to overwrite") && stderr.contains("sm"),
        "expected a refusal message, got:\n{stderr}"
    );
    // The foreign file must be untouched.
    let content = std::fs::read_to_string(bindir.join("sm")).unwrap();
    assert!(content.contains("not secret-manager"));

    // Now point `sm` at some other real program (a symlink, but not to
    // secret-manager): uninstall must leave it alone too.
    std::fs::remove_file(bindir.join("sm")).unwrap();
    std::os::unix::fs::symlink("some-other-program", bindir.join("sm")).unwrap();
    let uninstall = std::process::Command::new("make")
        .args(["uninstall"])
        .arg(format!("DESTDIR={}", stage.display()))
        .arg("PAMDIR=/usr/lib/security")
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        uninstall.status.success(),
        "uninstall failed:\n{}",
        String::from_utf8_lossy(&uninstall.stderr)
    );
    assert_eq!(
        std::fs::read_link(bindir.join("sm")).unwrap(),
        PathBuf::from("some-other-program"),
        "uninstall must not remove a symlink it did not create"
    );
}

/// The shipped unit must at least parse; the only expected diagnostic on a
/// machine without the package installed is the missing binary.
#[test]
fn systemd_analyze_verify_accepts_unit() {
    if std::process::Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping: systemd-analyze not on PATH");
        return;
    }
    let out = std::process::Command::new("systemd-analyze")
        .args(["--user", "verify", "dist/secret-manager.service"])
        .current_dir(root())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    for line in stderr.lines() {
        assert!(
            line.contains("is not executable") || line.contains("No such file or directory"),
            "unexpected systemd-analyze diagnostic: {line}"
        );
    }
}
