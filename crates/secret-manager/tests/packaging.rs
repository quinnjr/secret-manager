//! Sanity checks on the shipped unit, activation, and Makefile install list.

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn unit_and_activation_files_agree() {
    let unit = std::fs::read_to_string(root().join("dist/secret-manager.service")).unwrap();
    assert!(unit.contains("Type=dbus"));
    assert!(unit.contains("BusName=org.freedesktop.secrets"));
    assert!(unit.contains("ExecStart=/usr/bin/secret-manager daemon --foreground"));
    assert!(unit.contains("Conflicts=gnome-keyring-daemon.service"));
    // Memory-exposure hardening.
    assert!(unit.contains("LimitCORE=0"));
    assert!(unit.contains("PrivateTmp=yes"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=full"));
    assert!(unit.contains("RuntimeDirectory=secret-manager"));
    assert!(unit.contains("RuntimeDirectoryMode=0700"));
    assert!(unit.contains("ProtectKernelTunables=yes"));
    assert!(unit.contains("RestrictSUIDSGID=yes"));
    assert!(!unit.contains("ReadWritePaths"));
    let activation =
        std::fs::read_to_string(root().join("dist/org.freedesktop.secrets.service")).unwrap();
    assert!(activation.contains("Name=org.freedesktop.secrets"));
    assert!(activation.contains("SystemdService=secret-manager.service"));
    let env =
        std::fs::read_to_string(root().join("dist/environment.d/50-secret-manager.conf")).unwrap();
    assert!(env.contains("SSH_ASKPASS=/usr/bin/sm-askpass"));
    assert!(env.contains("SSH_ASKPASS_REQUIRE=prefer"));
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
    ] {
        assert!(text.contains(needle), "missing {needle} in:\n{text}");
    }
}
