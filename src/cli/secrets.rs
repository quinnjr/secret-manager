//! get / set / delete / list, argument-compatible with `secret-tool`.

use super::client::{Client, ItemInfo};
use super::{CliError, read_secret_from_stdin};
// A terminal row and a dialog line have the same problem, so they use the
// same escaper, and it lives in `crate::sanitize` — always compiled,
// because `src/vault/` is the PAM cdylib's half of the crate too, and the
// PAM module has peer-supplied text of its own to render. This file used to
// carry its own copy of the function *and* of the character table, and the
// table was the narrower one: it omitted the private-use planes, the Arabic
// number signs, the interlinear annotations and the tag characters — all of
// which a font may render as anything at all, or as nothing — so a planted
// item could hide part of an `sm ssh list` row that the dialogs already
// refused to hide. Found by `fuzz_targets/escape_control_sanitize.rs` on
// U+F0000; one definition is what stops the two drifting again, and the
// re-export keeps `super::secrets::escape_control` working for the dozens of
// call sites (and for `crate::fuzz_api`) that name it here.
use std::collections::{BTreeMap, HashSet};
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
/// something already matched (`sm get`, `sm ssh`). `sm list` is not a caller:
/// it never unlocks and prompts for nothing, so it walks the collections
/// itself.
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

/// Message used whenever a strict search cannot account for every locked
/// match. Named so `sm delete` and `sm ssh remove` report it identically.
pub(crate) const INCOMPLETE_UNLOCK: &str = "could not unlock every match; nothing was deleted";

/// Every path we asked to unlock must be present in the result. The daemon
/// reports `dismissed = false` as soon as *one* collection in the prompt
/// opened, listing only the paths that actually unlocked, so an `Ok` result is
/// not by itself proof that the whole set is reachable.
fn covers_all(items: &[OwnedObjectPath], locked: &[OwnedObjectPath]) -> bool {
    // Both slices are `SearchItems` results, so their length is bounded only
    // by how many items exist: the membership test is built once rather than
    // rescanned per locked path.
    let have: HashSet<&OwnedObjectPath> = items.iter().collect();
    locked.iter().all(|p| have.contains(p))
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
            let more = unlocked?;
            items.extend(more);
            if !covers_all(&items, &locked) {
                return Err(CliError::NotFound(INCOMPLETE_UNLOCK.into()));
            }
        } else {
            merge_unlocked(&mut items, unlocked)?;
        }
    }
    Ok(items)
}

/// Render a string for a terminal: labels and attribute values come from argv
/// or from any bus client, so a `\r`, an ANSI escape or a bidi override could
/// erase, forge or reorder `sm list` rows. Anything below U+0020, plus DEL and
/// the invisible formatters, becomes `\xNN` per UTF-8 byte.
///
/// One definition, in `crate::sanitize`; see the note at the top of this file.
pub(crate) use crate::sanitize::escape_control;

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
    fn covers_all_rejects_a_partial_unlock() {
        let a = OwnedObjectPath::try_from("/a").unwrap();
        let b = OwnedObjectPath::try_from("/b").unwrap();
        // The daemon answered `dismissed = false` but only listed `/a`.
        assert!(
            !covers_all(std::slice::from_ref(&a), &[a.clone(), b.clone()]),
            "a shortfall must not read as success"
        );
        assert!(covers_all(&[a.clone(), b.clone()], &[a, b]));
        assert!(covers_all(&[], &[]));
    }

    #[test]
    fn escape_control_hides_terminal_control_sequences() {
        assert_eq!(escape_control("plain"), "plain");
        assert_eq!(escape_control("a\rb"), "a\\x0db");
        assert_eq!(escape_control("a\nb\tc"), "a\\x0ab\\x09c");
        assert_eq!(escape_control("\u{1b}[2Kgone"), "\\x1b[2Kgone");
        assert_eq!(escape_control("\u{7f}"), "\\x7f");
        // Non-ASCII text is untouched.
        assert_eq!(escape_control("clé"), "clé");
    }

    /// MEDIUM 3: `char::is_control` is category Cc only, so the bidi and
    /// zero-width formatters used to visually reorder or hide a row survive
    /// it. They are escaped byte by byte like any other control character.
    #[test]
    fn escape_control_hides_unicode_format_characters() {
        // RIGHT-TO-LEFT OVERRIDE reverses everything after it.
        assert_eq!(escape_control("a\u{202e}b"), "a\\xe2\\x80\\xaeb");
        // Soft hyphen, Arabic letter mark, zero width space/joiners and the
        // bidi marks, the line/paragraph separators, the invisible operators,
        // the remaining bidi controls, and the byte order mark.
        for ch in [
            '\u{00ad}', '\u{061c}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}',
            '\u{2028}', '\u{2029}', '\u{202a}', '\u{202e}', '\u{2060}', '\u{2064}', '\u{2066}',
            '\u{206f}', '\u{feff}',
        ] {
            let escaped = escape_control(&ch.to_string());
            assert!(
                !escaped.contains(ch),
                "U+{:04X} reached the terminal: {escaped:?}",
                ch as u32
            );
            assert!(
                escaped.starts_with("\\x"),
                "U+{:04X}: {escaped:?}",
                ch as u32
            );
        }
        // The wider table the dialogs use, which this file once undercut: the
        // private-use planes (a font renders these as whatever it likes), the
        // Arabic number signs (which absorb the digits after them), the
        // interlinear annotations and the invisible tag characters. Red
        // before `is_invisible_format` became one shared table.
        for ch in [
            '\u{e000}',
            '\u{f8ff}',
            '\u{f0000}',
            '\u{100000}',
            '\u{0600}',
            '\u{06dd}',
            '\u{070f}',
            '\u{180e}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{1d173}',
            '\u{e0001}',
            '\u{e0020}',
            '\u{e007f}',
        ] {
            let escaped = escape_control(&ch.to_string());
            assert!(
                !escaped.contains(ch),
                "U+{:04X} reached the terminal: {escaped:?}",
                ch as u32
            );
        }
        // Characters just outside the escaped ranges are still printable text.
        for ch in ['\u{2065}', '\u{2070}', '\u{061d}', '\u{00ae}'] {
            assert_eq!(escape_control(&ch.to_string()), ch.to_string());
        }
    }

    /// MEDIUM 4: a delete that stops half-way must say so, and say which half.
    /// That is the one-at-a-time fallback path; see
    /// `an_atomic_batch_failure_says_nothing_was_deleted` for the batch path.
    #[test]
    fn a_partial_delete_names_what_survived() {
        assert_eq!(partial_delete_report(3, &[], &[]), None);
        let failed = vec![
            (
                "/org/x/item/1".to_string(),
                "collection is locked".to_string(),
            ),
            (
                "/org/x/item/2".to_string(),
                "collection is locked".to_string(),
            ),
        ];
        let msg = partial_delete_report(1, &failed, &[]).expect("a failure must be reported");
        assert!(msg.contains("deleted 1 item(s)"), "{msg}");
        assert!(msg.contains("2 could not be deleted"), "{msg}");
        assert!(msg.contains("still exists"), "{msg}");
        assert!(
            msg.contains("/org/x/item/1") && msg.contains("/org/x/item/2"),
            "{msg}"
        );
        // The reason is daemon-supplied text; it is escaped like any other.
        let hostile = vec![("/i".to_string(), "gone\rdeleted everything".to_string())];
        let msg = partial_delete_report(0, &hostile, &[]).unwrap();
        assert!(!msg.contains('\r') && msg.contains("\\x0d"), "{msg}");
    }

    /// A batch that the daemon refuses is all-or-nothing, so the message must
    /// say the secrets were left untouched rather than naming survivors — the
    /// user has nothing to clean up and nothing half-deleted to hunt for.
    #[test]
    fn an_atomic_batch_failure_says_nothing_was_deleted() {
        let untouched = vec![(
            "/org/freedesktop/secrets/collection/default".to_string(),
            3,
            "collection is locked".to_string(),
        )];
        let msg = partial_delete_report(0, &[], &untouched).expect("a failure must be reported");
        assert!(msg.contains("3 item(s)"), "{msg}");
        assert!(msg.contains("left untouched"), "{msg}");
        assert!(msg.contains("collection/default"), "{msg}");
        assert!(
            !msg.contains("still exists"),
            "a rejected batch has no survivors to warn about: {msg}"
        );
        // Daemon-supplied text is escaped here too.
        let hostile = vec![("/c".to_string(), 1, "no\rall gone".to_string())];
        let msg = partial_delete_report(0, &[], &hostile).unwrap();
        assert!(!msg.contains('\r') && msg.contains("\\x0d"), "{msg}");
    }

    /// Items are batched per collection, in input order, and a path that names
    /// no collection is left to the one-at-a-time fallback.
    #[test]
    fn items_group_by_their_collection() {
        let p = |s: &str| OwnedObjectPath::try_from(s.to_string()).unwrap();
        let groups = group_paths_by_owner(&[
            p("/org/freedesktop/secrets/collection/default/a"),
            p("/org/freedesktop/secrets/collection/work/b"),
            p("/org/freedesktop/secrets/collection/default/c"),
            p("/org/freedesktop/secrets/aliases/login/d"),
            p("/nonsense"),
        ]);
        assert_eq!(groups.len(), 4);
        assert_eq!(
            groups[0].0.as_ref().unwrap().as_str(),
            "/org/freedesktop/secrets/collection/default"
        );
        assert_eq!(groups[0].1.len(), 2, "same collection batches together");
        assert_eq!(
            groups[1].0.as_ref().unwrap().as_str(),
            "/org/freedesktop/secrets/collection/work"
        );
        assert_eq!(
            groups[2].0.as_ref().unwrap().as_str(),
            "/org/freedesktop/secrets/aliases/login"
        );
        assert_eq!(groups[3].0, None, "an unattributable path is not batched");
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
    let found = find(&client, &query).await?;
    let mut best: Option<ItemInfo> = None;
    let mut matches = 0usize;
    for path in &found {
        let info = client.item_info(path).await?;
        if label.as_deref().is_some_and(|l| l != info.label) {
            continue;
        }
        matches += 1;
        if best.as_ref().is_none_or(|b| info.modified > b.modified) {
            best = Some(info);
        }
    }
    let Some(info) = best else {
        return Err(CliError::NotFound("no matching secret".into()));
    };
    // `SearchItems` is subset matching, so an item carrying the queried
    // attributes *plus* its own also matches; any process on the session bus
    // can create one and win on `modified`. Keep secret-tool's "newest wins"
    // behaviour and exit code, but never do it silently.
    if matches > 1 {
        eprintln!(
            "warning: {matches} items match; using the most recently modified (\"{}\"). \
             Pass --label to disambiguate.",
            escape_control(&info.label)
        );
    }
    let path = info.path;
    let secret = client.get_secret(&path).await?;
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
    delete_each(&client, &items).await
}

/// Delete every item, then report.
///
/// Items are grouped by collection and each group goes to the daemon in one
/// atomic `DeleteItems` call (the private batch interface — the freedesktop
/// spec has no batch delete), so a collection that locks part-way through, or
/// a daemon that dies mid-write, leaves that collection's set entirely deleted
/// or entirely intact. N separate `Item.Delete` calls could not promise that.
///
/// The one-at-a-time path is kept as the fallback for a daemon that does not
/// export the batch interface. `find_all` proves each locked match was opened,
/// but the collection can still lock (an idle timer, a `sm lock` from another
/// terminal) between then and the delete, so that path keeps going and names
/// what was removed and what was not. On the batch path there are no
/// survivors to name: the group was left untouched.
pub(crate) async fn delete_each(
    client: &Client,
    items: &[OwnedObjectPath],
) -> Result<(), CliError> {
    let mut deleted = 0usize;
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut untouched: Vec<(String, usize, String)> = Vec::new();
    for (collection, paths) in group_paths_by_owner(items) {
        // A path we cannot attribute to a collection cannot be batched; it is
        // almost certainly stale, and `Item.Delete` will say so.
        let batched = match &collection {
            Some(c) => client.delete_items(c, &paths).await,
            None => Ok(false),
        };
        match batched {
            Ok(true) => deleted += paths.len(),
            // No batch interface on this daemon: fall back, honestly.
            Ok(false) => {
                for item in &paths {
                    match client.delete_item(item).await {
                        Ok(()) => deleted += 1,
                        Err(e) => failed.push((item.to_string(), e.to_string())),
                    }
                }
            }
            Err(e) => untouched.push((
                collection.map(|c| c.to_string()).unwrap_or_default(),
                paths.len(),
                e.to_string(),
            )),
        }
    }
    match partial_delete_report(deleted, &failed, &untouched) {
        Some(msg) => Err(CliError::Failed(msg)),
        None => Ok(()),
    }
}

/// Item paths grouped by the collection they live in, preserving the input
/// order within each group. A path that is not an item path under a collection
/// or alias groups under `None`.
///
/// Hashed index rather than a linear `find` per element, matching the
/// `group_by_collection` in `dbus::service`; buckets come back in
/// first-appearance order with each group's paths in input order.
fn group_paths_by_owner(
    items: &[OwnedObjectPath],
) -> Vec<(Option<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
    use crate::dbus::paths::{self, Target};
    use std::collections::HashMap;
    let mut groups: Vec<(Option<OwnedObjectPath>, Vec<OwnedObjectPath>)> = Vec::new();
    let mut at: HashMap<Option<OwnedObjectPath>, usize> = HashMap::new();
    for item in items {
        let owner = match paths::parse(item.as_str()) {
            Some(Target::Item { collection, .. }) => Some(paths::collection(&collection)),
            Some(Target::AliasItem { alias, .. }) => paths::alias(&alias),
            _ => None,
        };
        match at.get(&owner) {
            Some(&slot) => groups[slot].1.push(item.clone()),
            None => {
                at.insert(owner.clone(), groups.len());
                groups.push((owner, vec![item.clone()]));
            }
        }
    }
    groups
}

/// The message for a delete that could not finish, or `None` if it did.
/// Separate from the loop so the wording is testable without a bus.
///
/// `failed` are individual items from the one-at-a-time fallback, which really
/// can leave survivors. `untouched` are whole batches that were rejected
/// atomically: nothing in them was deleted, so the wording must not invite the
/// user to go hunting for a half-deleted set.
fn partial_delete_report(
    deleted: usize,
    failed: &[(String, String)],
    untouched: &[(String, usize, String)],
) -> Option<String> {
    if failed.is_empty() && untouched.is_empty() {
        return None;
    }
    let mut msg = String::new();
    if !failed.is_empty() {
        msg.push_str(&format!(
            "deleted {deleted} item(s), but {} could not be deleted; \
             the secret still exists in the collection",
            failed.len()
        ));
        for (path, why) in failed {
            msg.push_str(&format!(
                "\n  {}: {}",
                escape_control(path),
                escape_control(why)
            ));
        }
    }
    for (collection, n, why) in untouched {
        if !msg.is_empty() {
            msg.push('\n');
        }
        msg.push_str(&format!(
            "{n} item(s) in {} were left untouched: {}",
            escape_control(collection),
            escape_control(why)
        ));
    }
    Some(msg)
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
                .map(|(k, v)| format!("{}={}", escape_control(k), escape_control(v)))
                .collect();
            writeln!(out, "{}\t{}", escape_control(&e.label), attrs.join(" "))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod parse_attrs_tests {
    use super::*;

    /// `split_once('=')` accepts `"=value"` happily -- the empty name is only
    /// rejected by the `.filter(|(k, _)| !k.is_empty())` after it. An empty
    /// attribute name would go into the query map and match against a stored
    /// attribute set that can never contain it, so it is usage, not a search
    /// that quietly finds nothing.
    #[test]
    fn parse_attrs_rejects_a_missing_or_empty_name() {
        for bad in ["noequals", "=value", "="] {
            let err = parse_attrs(&[bad.to_string()]).unwrap_err();
            assert!(matches!(err, CliError::Usage(_)), "{bad}: got {err:?}");
            assert!(err.to_string().contains("ATTR=VALUE"), "{bad}: {err}");
        }
    }

    /// Only the *name* may not be empty: `sm get schema=` is a legitimate
    /// search for an attribute stored with an empty value.
    #[test]
    fn parse_attrs_keeps_an_empty_value() {
        let attrs = parse_attrs(&["a=".to_string(), "b=v".to_string()]).unwrap();
        assert_eq!(attrs.get("a").map(String::as_str), Some(""));
        assert_eq!(attrs.get("b").map(String::as_str), Some("v"));
    }
}
