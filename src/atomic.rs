//! One atomic file write, shared by every writer in this crate.
//!
//! The vault saves, the alias file, and the import report all used to carry
//! their own copy of the same sequence — an `O_EXCL` temp file beside the
//! target, `fsync`, `rename` over the target, best-effort directory `fsync`
//! — and three copies of "in what order, with what flags" is the drift that
//! shows up as a truncated file behind a crash. This is the single
//! definition. Callers that must create the parent directory first (the vault
//! and alias writers, via `vault::store::ensure_vault_dir`) do so before
//! calling; the temp name carries the target's file name so the vault's
//! stale-temp sweep recognises what this produces.

use std::path::Path;

/// Write `bytes` to `path` atomically: a fresh `O_EXCL` temp file beside it
/// carrying `mode`, `fsync`, `rename` over the target, best-effort directory
/// `fsync`.
///
/// `mode` applies at creation, as `OpenOptions::mode` does — pass `0o600`
/// for files that name labels or attribute keys, `0o666` to keep the
/// historic default (`0666 & ~umask`) of a writer that never set one.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    let suffix: [u8; 8] = crate::vault::crypto::try_random_bytes().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            format!("the system RNG is unavailable: {e}"),
        )
    })?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let temp = dir.join(format!("{name}.{suffix}.tmp"));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let write = || -> std::io::Result<()> {
        let mut f = options.open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&temp, path)
    };
    match write() {
        Ok(()) => {
            // Best effort: the rename is already durable enough that a reader
            // never sees a partial file, and failing the write over an
            // unsyncable directory is the worse trade.
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&temp);
            Err(e)
        }
    }
}
