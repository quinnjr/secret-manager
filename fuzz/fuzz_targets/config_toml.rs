//! `config.toml` as text.
//!
//! The config file is the least hostile input in this codebase — it lives in
//! the user's own `$XDG_CONFIG_HOME` and is read by a process running as that
//! user — but it is still parsed before anything else happens, by the daemon,
//! the CLI and (through `load_config`) `sm-askpass`, so a panic in it is a
//! startup denial of service that a stray editor artifact could cause. It is
//! also the one place a *weak* KDF can be requested by name (audit L10): the
//! ceilings that protect the vault header have to apply here too, because a
//! vault created under this config is stuck with whatever it says.
//!
//! So the target asserts what an accepted config guarantees, not merely that
//! parsing terminated: every accepted `Config` carries KDF parameters that
//! `KdfParams::validate` would accept, which is the same check the vault
//! header goes through before Argon2 is allowed to run.
#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use secret_manager::config::Config;
use secret_manager::vault::crypto::KdfParams;

fn check(c: &Config, text: &str) {
    let params: KdfParams = c.kdf.into();
    // The ceilings are the whole point: `m_cost_kib` above them is an
    // out-of-memory at startup, and a zero `t_cost`/`p_cost` is an Argon2
    // parameter error at the first derivation rather than at load.
    assert!(
        params.validate().is_ok(),
        "an accepted config carries unusable KDF parameters {params:?}: {text:?}"
    );
    assert!(params.p_cost >= 1 && params.p_cost <= KdfParams::MAX_P_COST);
    assert!(params.t_cost >= 1 && params.t_cost <= KdfParams::MAX_T_COST);
    assert!(params.m_cost_kib <= KdfParams::MAX_M_COST_KIB);
    // Argon2's own floor. Below it every derivation errors out, which would
    // make the vault unopenable rather than weak.
    assert!(params.m_cost_kib >= 8 * params.p_cost);

    // `~` is expanded at parse time; a path that still begins with one would
    // be created as a literal directory called `~` in the cwd.
    assert!(
        !c.vault.dir.starts_with("~"),
        "an unexpanded tilde survived: {:?} from {text:?}",
        c.vault.dir
    );

    // Parsing is a fixed point on its own output shape: the same text must
    // always give the same config, so a value cannot mean one thing at the
    // ceiling check and another when the vault is created from it.
    match Config::from_str(text) {
        Ok(again) => assert_eq!(*c, again, "config parsing is not deterministic"),
        Err(e) => panic!("text that parsed once did not parse again: {text:?}: {e}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // The raw form: arbitrary bytes as TOML. This is what a truncated write
    // or a wrong file actually looks like.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(c) = Config::from_str(text) {
            check(&c, text);
        }
    }

    // The structured form: a syntactically valid config whose *values* are
    // hostile, which is where the ceiling check lives. Uniform bytes almost
    // never produce a parsable `[kdf]` table, so without this the target
    // would only ever measure the TOML parser.
    let (Ok(m), Ok(t), Ok(p)) = (
        u.arbitrary::<u32>(),
        u.arbitrary::<u32>(),
        u.arbitrary::<u32>(),
    ) else {
        return;
    };
    let Ok(dir) = smfuzz::hostile_string(&mut u) else {
        return;
    };
    let Ok(secs) = u.arbitrary::<u64>() else {
        return;
    };
    let text = format!(
        "[vault]\ndir = {dir:?}\nauto_lock_after = \"{secs}s\"\n\
         [kdf]\nm_cost_kib = {m}\nt_cost = {t}\np_cost = {p}\n"
    );
    if let Ok(c) = Config::from_str(&text) {
        check(&c, &text);
        assert_eq!(c.kdf.m_cost_kib, m);
        assert_eq!(c.kdf.t_cost, t);
        assert_eq!(c.kdf.p_cost, p);
    }

    // Unknown keys are refused (`deny_unknown_fields`), so a typo is an error
    // at load rather than a setting that silently did nothing.
    assert!(Config::from_str("[kdf]\nm_cost_kib_typo = 1\n").is_err());
    assert!(Config::from_str("[nope]\nx = 1\n").is_err());
});
