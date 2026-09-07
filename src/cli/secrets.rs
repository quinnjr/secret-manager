//! get / set / delete / list, argument-compatible with `secret-tool`.

use super::client::{Client, ItemInfo};
use super::{CliError, read_secret_from_stdin};
use std::collections::BTreeMap;
use std::io::Write;
use zbus::zvariant::OwnedObjectPath;

pub fn parse_attrs(args: &[String]) -> Result<BTreeMap<String, String>, CliError> {
    let mut out = BTreeMap::new();
    for a in args {
        let (k, v) = a
            .split_once('=')
            .filter(|(k, _)| !k.is_empty())
            .ok_or_else(|| CliError::Usage(format!("expected ATTR=VALUE, got '{a}'")))?;
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

/// Merge an unlock attempt's newly-unlocked items into `items`. Only a
/// dismissed prompt is absorbed, and only when something already matched;
/// a dead daemon or a real failure still fails the command, so the user is
/// never told "nothing matched" when the truth is "we could not look".
fn merge_unlocked(
    items: &mut Vec<OwnedObjectPath>,
    result: Result<Vec<OwnedObjectPath>, CliError>,
) -> Result<(), CliError> {
    match result {
        Ok(more) => {
            items.extend(more);
            Ok(())
        }
        Err(CliError::NotFound(_)) if !items.is_empty() => Ok(()),
        Err(e) => Err(e),
    }
}

/// Search, unlocking what is locked. A dismissed prompt is tolerated when
/// something already matched (`sm get`, `sm list`, `sm ssh`).
pub(crate) async fn find(
    client: &Client,
    query: &BTreeMap<String, String>,
) -> Result<Vec<OwnedObjectPath>, CliError> {
    find_inner(client, query, false).await
}

/// Search, requiring every locked match to be unlocked. Used by `sm delete`,
/// where a partial result would silently delete some copies of a secret and
/// still report success.
pub(crate) async fn find_all(
    client: &Client,
    query: &BTreeMap<String, String>,
) -> Result<Vec<OwnedObjectPath>, CliError> {
    find_inner(client, query, true).await
}

async fn find_inner(
    client: &Client,
    query: &BTreeMap<String, String>,
    strict: bool,
) -> Result<Vec<OwnedObjectPath>, CliError> {
    let (mut items, locked) = client.search(query).await?;
    if !locked.is_empty() {
        let unlocked = client.unlock(&locked).await;
        if strict {
            items.extend(unlocked?);
        } else {
            merge_unlocked(&mut items, unlocked)?;
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_unlocked_still_fails_on_a_transport_error() {
        let mut items = vec![OwnedObjectPath::try_from("/a").unwrap()];
        let err = CliError::Unreachable("daemon went away".into());
        assert!(
            merge_unlocked(&mut items, Err(err)).is_err(),
            "a dead daemon must not look like an empty result"
        );
    }

    #[test]
    fn merge_unlocked_keeps_prior_matches_on_dismissal() {
        let mut items = vec![OwnedObjectPath::try_from("/a").unwrap()];
        let err = CliError::NotFound("password prompt dismissed".into());
        assert!(merge_unlocked(&mut items, Err(err)).is_ok());
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn merge_unlocked_fails_when_nothing_matched_yet() {
        let mut items: Vec<OwnedObjectPath> = Vec::new();
        let err = CliError::NotFound("password prompt dismissed".into());
        assert!(merge_unlocked(&mut items, Err(err)).is_err());
    }

    #[test]
    fn merge_unlocked_extends_on_success() {
        let mut items: Vec<OwnedObjectPath> = Vec::new();
        let more = vec![OwnedObjectPath::try_from("/b").unwrap()];
        assert!(merge_unlocked(&mut items, Ok(more)).is_ok());
        assert_eq!(items.len(), 1);
    }
}

pub async fn get(attrs: Vec<String>, label: Option<String>) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    let client = Client::connect().await?;
    let mut best: Option<ItemInfo> = None;
    for path in find(&client, &query).await? {
        let info = client.item_info(&path).await?;
        if label.as_deref().is_some_and(|l| l != info.label) {
            continue;
        }
        if best.as_ref().is_none_or(|b| info.modified > b.modified) {
            best = Some(info);
        }
    }
    let Some(info) = best else {
        return Err(CliError::NotFound("no matching secret".into()));
    };
    let secret = client.get_secret(&info.path).await?;
    let mut out = std::io::stdout().lock();
    out.write_all(&secret)?;
    out.flush()?;
    Ok(())
}

pub async fn set(attrs: Vec<String>, label: String) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    if query.is_empty() {
        return Err(CliError::Usage(
            "at least one ATTR=VALUE is required".into(),
        ));
    }
    let secret = read_secret_from_stdin()?;
    let client = Client::connect().await?;
    client.store(&query, &label, &secret).await?;
    Ok(())
}

pub async fn delete(attrs: Vec<String>) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    if query.is_empty() {
        return Err(CliError::Usage(
            "at least one ATTR=VALUE is required".into(),
        ));
    }
    let client = Client::connect().await?;
    // Strict: if a locked match cannot be unlocked, delete nothing rather
    // than report success after removing only part of the set.
    let items = find_all(&client, &query).await?;
    if items.is_empty() {
        return Err(CliError::NotFound("no matching secret".into()));
    }
    for item in &items {
        client.delete_item(item).await?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ListEntry {
    path: String,
    label: String,
    attributes: BTreeMap<String, String>,
    locked: bool,
    modified: u64,
}

/// Labels and attributes only. Locked items show as `[locked]`; no prompt is raised.
pub async fn list(attrs: Vec<String>, json: bool) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    let client = Client::connect().await?;
    let paths = if query.is_empty() {
        client.all_items().await?
    } else {
        let (mut u, l) = client.search(&query).await?;
        u.extend(l);
        u
    };
    let mut entries = Vec::new();
    for p in paths {
        let info = client.item_info(&p).await?;
        entries.push(ListEntry {
            path: info.path.to_string(),
            label: if info.locked {
                "[locked]".to_string()
            } else {
                info.label
            },
            attributes: info.attributes,
            locked: info.locked,
            modified: info.modified,
        });
    }
    let mut out = std::io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &entries)
            .map_err(|e| CliError::Failed(e.to_string()))?;
        writeln!(out)?;
    } else {
        for e in entries {
            let attrs: Vec<String> = e
                .attributes
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            writeln!(out, "{}\t{}", e.label, attrs.join(" "))?;
        }
    }
    Ok(())
}
