//! gpg enroll / preset (CLI).
//!
//! Passphrases live as ordinary items (`xdg:schema=org.secret-manager.gpg`,
//! `keyid=<LONGID>`); the parsing, homedir resolution and agent protocol
//! live in [`crate::gpg`] so the daemon's unlock hook shares them.
//! `enroll` prompts once, stores, presets the agent and proves the
//! roundtrip with a `--batch` testsign that cannot prompt. `preset`
//! re-applies every enrolled key (honouring `[gpg] keys`) and is also what
//! runs manually when the daemon path is not enabled.

use super::client::Client;
use super::secrets::{delete_each, find_all};
use super::{CliError, load_config};
use crate::gpg::{self, Bins, SecretKey};
use clap::Subcommand;
use std::io::Write;
use std::process::Stdio;
use zeroize::Zeroizing;

#[derive(Subcommand, Debug)]
pub enum GpgCommand {
    /// Store a signing key's passphrase and verify it end to end
    Enroll {
        /// Long key id (or fingerprint); omitted when exactly one signing key exists
        #[arg(long)]
        keyid: Option<String>,
    },
    /// Feed every enrolled passphrase to gpg-agent (login helper)
    Preset,
}

/// One resolution path for both surfaces: the daemon reads the same
/// fields, so a config that presets at unlock also enrolls and presets
/// by hand.
///
/// `enroll` fails closed on an unreadable config (it stores a secret:
/// discovering the wrong ring would strand it). `preset` warns and
/// proceeds on defaults instead, because the login helper must not fail
/// the boot on a typo elsewhere in the file — one warning covers both
/// the binaries/homedir and the key filter, so the two halves of one
/// section cannot drift into silent-vs-loud disagreement.
fn bins_or_warn() -> (Bins, Vec<String>, Option<String>) {
    match load_config() {
        Ok(c) => (Bins::from_config(&c.gpg), c.gpg.keys, None),
        Err(e) => (
            Bins::from_env(),
            Vec::new(),
            Some(format!("warning: unreadable config ({e}); using defaults")),
        ),
    }
}

fn pick_key(keys: Vec<SecretKey>, wanted: Option<&str>) -> Result<SecretKey, CliError> {
    match wanted {
        Some(id) => {
            let mut matches = keys.into_iter().filter(|k| gpg::keyid_matches(id, &k.fpr));
            match (matches.next(), matches.next()) {
                (Some(one), None) => Ok(one),
                (None, _) => Err(CliError::NotFound(format!(
                    "no secret signing key matches {id}"
                ))),
                (Some(_), Some(_)) => Err(CliError::Usage(format!(
                    "{id} matches several secret keys; pass a full fingerprint"
                ))),
            }
        }
        None => {
            let mut keys = keys.into_iter();
            match (keys.next(), keys.next()) {
                (Some(one), None) => Ok(one),
                (None, _) => Err(CliError::NotFound("no secret signing keys found".into())),
                (Some(_), Some(_)) => Err(CliError::Usage(
                    "more than one secret signing key found; pass --keyid to choose one".into(),
                )),
            }
        }
    }
}

/// `--batch` cannot prompt, so a success proves the preset took and a
/// failure proves it did not — without ever popping a dialog. Pinned to
/// the enrolled key: proving a *different* key would make the roundtrip
/// vacuous on multi-key rings.
fn testsign(bins: &Bins, key: &SecretKey) -> Result<(), CliError> {
    let mut child = std::process::Command::new(&bins.gpg)
        .arg("--homedir")
        .arg(&bins.homedir)
        .args(["--batch", "--clearsign", "--local-user", &key.fpr])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| CliError::Failed(format!("cannot run gpg: {e}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::Failed("gpg has no stdin".into()))?;
    if let Err(e) = stdin.write_all(b"secret-manager enroll check") {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CliError::Failed(format!(
            "cannot feed gpg testsign input: {e}"
        )));
    }
    drop(stdin);
    if gpg::wait_bounded(child, "gpg --clearsign")
        .map_err(|e| CliError::Failed(e.to_string()))?
        .status
        .success()
    {
        Ok(())
    } else {
        Err(CliError::Failed(
            "verification testsign failed; the passphrase is stored but the agent \
             would still prompt — is `allow-preset-passphrase` set and the agent reloaded?"
                .into(),
        ))
    }
}

fn gpg_error(e: gpg::GpgError) -> CliError {
    CliError::Failed(e.to_string())
}

/// Item paths whose stored `keyid` names `fpr`, in any accepted spelling.
/// The vault index matches exactly, so the join happens here — the same
/// normalization the daemon's scan applies, over the same persisted
/// schema.
async fn find_key_items(
    client: &Client,
    query: &std::collections::BTreeMap<String, String>,
    fpr: &str,
) -> Result<Vec<zbus::zvariant::OwnedObjectPath>, CliError> {
    let mut out = Vec::new();
    for path in find_all(client, query).await? {
        let info = client.item_info(&path).await?;
        if info
            .attributes
            .get("keyid")
            .is_some_and(|k| gpg::keyid_matches(k, fpr))
        {
            out.push(path);
        }
    }
    Ok(out)
}

fn schema_query() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([("xdg:schema".to_string(), gpg::GPG_SCHEMA.to_string())])
}

pub async fn enroll(keyid: Option<String>) -> Result<(), CliError> {
    // Fail closed: an unreadable config must not discover the wrong ring
    // and strand a freshly stored secret where the daemon never looks.
    let cfg = load_config()
        .map(|c| c.gpg)
        .map_err(|e| CliError::Failed(format!("cannot enroll with an unreadable config: {e}")))?;
    let bins = Bins::from_config(&cfg);
    let keys = gpg::discover(&bins).map_err(|e| match e {
        gpg::GpgError::Missing(_) => CliError::Failed("gpg not found on PATH".into()),
        other => gpg_error(other),
    })?;
    let key = pick_key(keys, keyid.as_deref())?;
    let longid = key.longid();
    let secret: Zeroizing<Vec<u8>> = Zeroizing::new(
        super::read_new_password(&format!("Passphrase for GPG key {longid}"))?
            .as_bytes()
            .to_vec(),
    );
    if secret.is_empty() {
        return Err(CliError::Usage(
            "empty passphrase: an unprotected key needs no preset".into(),
        ));
    }
    let client = Client::connect().await?;
    // Strict like `ssh add`: delete every spelling of this key's
    // registration, so a later preset cannot prefer a stale copy.
    delete_each(
        &client,
        &find_key_items(&client, &schema_query(), &key.fpr).await?,
    )
    .await?;
    client
        .store(
            &gpg::key_query(&longid),
            &format!("GPG signing key {longid}"),
            &secret,
        )
        .await?;
    // Stored; now prove the agent path before claiming success.
    gpg::preset_one(&bins, &key.grip, &secret).map_err(gpg_error)?;
    testsign(&bins, &key)?;
    println!("Enrolled GPG key {longid}; roundtrip verified");
    if !cfg.enabled {
        println!(
            "To preset at login, set [gpg] enabled = true and homedir = \"{}\" in {}",
            bins.homedir.display(),
            crate::config::config_file().display()
        );
    }
    Ok(())
}

pub async fn preset() -> Result<(), CliError> {
    let (bins, filter, warning) = bins_or_warn();
    if let Some(warning) = warning {
        eprintln!("{warning}");
    }
    let keys = match gpg::discover(&bins) {
        // No gpg, no keys: nothing to do, and the login helper must
        // never fail the boot on this — unless the operator configured
        // an explicit binary, which deserves an error rather than
        // silence.
        Err(gpg::GpgError::Missing(_)) if bins.gpg.components().count() == 1 => return Ok(()),
        Err(e) => return Err(gpg_error(e)),
        Ok(keys) => keys,
    };
    let Ok(client) = Client::connect().await else {
        eprintln!("warning: secret-manager unreachable; preset skipped");
        return Ok(());
    };
    // One schema-wide fetch, joined in code with the same normalization
    // the daemon's scan applies — an exact per-key query would miss
    // hand-written spellings the unlock hook happily presets. A fetch
    // that fails (locked and unopenable) counts as unreadable rather
    // than empty: silence would certify a preset that read nothing.
    let mut stored: Vec<(String, zbus::zvariant::OwnedObjectPath)> = Vec::new();
    let mut unreadable = 0usize;
    match find_all(&client, &schema_query()).await {
        Ok(paths) => {
            for path in paths {
                let Ok(info) = client.item_info(&path).await else {
                    unreadable += 1;
                    continue;
                };
                if let Some(keyid) = info.attributes.get("keyid") {
                    stored.push((keyid.clone(), path));
                }
            }
        }
        Err(_) => unreadable += 1,
    }
    let mut pairs = Vec::new();
    for key in &keys {
        let longid = key.longid();
        if !gpg::key_allowed(&filter, &longid) {
            continue;
        }
        // Several copies can share a keyid: try each until one reads
        // rather than letting the first decide.
        let mut secret = None;
        let mut candidates = 0usize;
        for (keyid, path) in &stored {
            if !gpg::keyid_matches(keyid, &key.fpr) {
                continue;
            }
            candidates += 1;
            if let Ok(s) = client.get_secret(path).await {
                secret = Some(s);
                break;
            }
        }
        let Some(secret) = secret else {
            if candidates > 0 {
                unreadable += 1;
            }
            continue;
        };
        if secret.is_empty() {
            eprintln!("warning: {longid} is enrolled with an empty passphrase; skipping");
            continue;
        }
        pairs.push((longid, secret));
    }
    let (done, failed) = gpg::preset_enrolled(&bins, &pairs);
    if !failed.is_empty() {
        return Err(CliError::Failed(failed.join("; ")));
    }
    if done > 0 {
        println!("Preset {done} GPG key(s)");
    }
    if unreadable > 0 {
        eprintln!("warning: {unreadable} enrolled key(s) could not be read");
    }
    if done == 0 && unreadable > 0 {
        return Err(CliError::Failed(
            "preset nothing: enrolled keys could not be read".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fpr: &str, grip: &str) -> SecretKey {
        SecretKey {
            fpr: fpr.into(),
            grip: grip.into(),
        }
    }

    #[test]
    fn pick_key_refuses_to_guess() {
        const FPR: &str = "214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E3";
        const GRIP: &str = "EFEB25D85B8B0F2835DE2591EA242763FE1FCCF9";
        let one = vec![key(FPR, GRIP)];
        assert!(pick_key(vec![], None).is_err());
        assert!(pick_key(one.clone(), None).is_ok());
        assert!(pick_key(one.clone(), Some("D98C3F305E74B9E3")).is_ok());
        assert!(pick_key(one, Some("DEADBEEF")).is_err());
        let two = vec![
            key(FPR, GRIP),
            key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "B"),
        ];
        let err = pick_key(two, None).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{err:?}");
    }

    #[test]
    fn an_explicit_id_matching_two_keys_is_refused() {
        // A 16-hex long-id collision in the ring: enrolling either would
        // store one passphrase under an id naming two keys.
        let two = vec![
            key("214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E3", "A"),
            key("FFFFFFFFFFFFFFFFFFFFFFFFFFFFD98C3F305E74B9E3", "B"),
        ];
        let err = pick_key(two, Some("D98C3F305E74B9E3")).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{err:?}");
    }
}
