//! The PAM module driven through a *real* libpam stack.
//!
//! Everything else that tests `src/pam/` tests the decision functions, which
//! compile without libpam. This binary tests the half that only exists inside
//! the `cdylib`: the `pam_module!` ABI, the `PamData` stash that has to survive
//! from the auth stack to the session stack, whether clearing that stash
//! actually lands, and what `get_user`/`get_cached_authtok` hand back.
//!
//! How it runs without root and without touching `/etc/pam.d`:
//!
//! * `pam_start_confdir` (glibc Linux-PAM ≥ 1.4) points libpam at a temporary
//!   config directory, so the service file is ours and names the built cdylib
//!   by absolute path.
//! * libpam is loaded with `dlopen` rather than linked, so a machine without
//!   it skips these tests instead of failing to build the suite.
//! * `PAM_AUTHTOK` cannot be set by an application — Linux-PAM refuses
//!   `pam_set_item(PAM_AUTHTOK)` from outside a module. `auth optional
//!   pam_unix.so nodelay` sits ahead of us in the stack: `pam_get_authtok`
//!   prompts through our conversation function and caches the answer into
//!   `PAM_AUTHTOK` *before* it verifies it, so the token is there even though
//!   the verify then fails (the vault password is not the login password) and
//!   `optional` lets the stack continue. `nodelay` suppresses pam_unix's two
//!   second failure delay.
//! * Nothing is passed through the environment: the module is dlopened into
//!   *this* process, so it would read this process's environment, and
//!   `set_var` is unsound in a parallel suite. `vault_dir=` and `socket=` are
//!   module arguments in the service file instead. `socket=` is honoured only
//!   below root, which this suite asserts it is.

mod common;

use common::Fixture;
use secret_manager::protocol::{Request, Response};
use secret_manager::vault::Vault;
use secret_manager::vault::crypto::KdfParams;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// libpam, loaded at runtime
// ---------------------------------------------------------------------------

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_CONV_ERR: c_int = 19;
const PAM_BUF_ERR: c_int = 5;
/// Bound on how many messages one conversation call is willing to answer.
/// Purely defensive: libpam sends one or two.
const MAX_CONV_MSGS: c_int = 32;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = unsafe extern "C" fn(
    c_int,
    *const *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

type StartConfdirFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const PamConv,
    *const c_char,
    *mut *mut c_void,
) -> c_int;
type StackFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;

/// The handful of libpam entry points these tests need. Only function
/// pointers are kept, so the struct is `Send + Sync`; the `dlopen` handle is
/// deliberately leaked, since libpam stays loaded for the life of the process.
struct Libpam {
    start_confdir: StartConfdirFn,
    authenticate: StackFn,
    open_session: StackFn,
    chauthtok: StackFn,
    end: StackFn,
}

// SAFETY: every field is a plain function pointer into a library that is never
// unloaded.
unsafe impl Send for Libpam {}
unsafe impl Sync for Libpam {}

fn load_libpam() -> Result<Libpam, String> {
    let handle = unsafe { libc::dlopen(c"libpam.so.0".as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        return Err("libpam.so.0 cannot be dlopened".to_string());
    }
    fn sym(handle: *mut c_void, name: &CStr) -> Result<*mut c_void, String> {
        let p = unsafe { libc::dlsym(handle, name.as_ptr()) };
        if p.is_null() {
            return Err(format!("libpam exports no {}", name.to_string_lossy()));
        }
        Ok(p)
    }
    // `pam_start_confdir` is the one that makes a rootless test possible; a
    // libpam older than 1.4 does not have it and these tests skip.
    let start_confdir = sym(handle, c"pam_start_confdir")?;
    let authenticate = sym(handle, c"pam_authenticate")?;
    let open_session = sym(handle, c"pam_open_session")?;
    let chauthtok = sym(handle, c"pam_chauthtok")?;
    let end = sym(handle, c"pam_end")?;
    // SAFETY: each pointer is the address of the correspondingly named libpam
    // function, transmuted to its documented C signature.
    unsafe {
        Ok(Libpam {
            start_confdir: std::mem::transmute::<*mut c_void, StartConfdirFn>(start_confdir),
            authenticate: std::mem::transmute::<*mut c_void, StackFn>(authenticate),
            open_session: std::mem::transmute::<*mut c_void, StackFn>(open_session),
            chauthtok: std::mem::transmute::<*mut c_void, StackFn>(chauthtok),
            end: std::mem::transmute::<*mut c_void, StackFn>(end),
        })
    }
}

// ---------------------------------------------------------------------------
// Conversation function
// ---------------------------------------------------------------------------

/// What the conversation function answers, chosen by substring of the prompt.
///
/// pam_unix asks `Password:` in the auth stack and `Current password:` /
/// `New password:` / `Retype new password:` in the password stack, so one
/// table covers every prompt any of these tests provokes.
struct Answers {
    /// Answer to the auth stack's `Password:`.
    auth: CString,
    /// Answer to `Current password:`.
    current: CString,
    /// Answer to `New password:` and `Retype new password:`.
    new: CString,
}

impl Answers {
    fn new(auth: &str, current: &str, new: &str) -> Answers {
        Answers {
            auth: CString::new(auth).unwrap(),
            current: CString::new(current).unwrap(),
            new: CString::new(new).unwrap(),
        }
    }

    /// Picks an answer without allocating or panicking: this runs on a stack
    /// frame owned by C and must not unwind.
    fn pick(&self, prompt: *const c_char) -> *const c_char {
        if prompt.is_null() {
            return self.auth.as_ptr();
        }
        let contains = |needle: &CStr| unsafe { !libc::strstr(prompt, needle.as_ptr()).is_null() };
        if contains(c"Current") {
            self.current.as_ptr()
        } else if contains(c"New") || contains(c"Retype") {
            self.new.as_ptr()
        } else {
            self.auth.as_ptr()
        }
    }
}

/// Called by libpam, from C. Allocates its reply with `calloc`/`strdup`
/// because libpam frees it with `free`, and contains nothing that can panic.
unsafe extern "C" fn converse(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || num_msg > MAX_CONV_MSGS || msg.is_null() || resp.is_null() {
        return PAM_CONV_ERR;
    }
    if appdata.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: `appdata_ptr` was set to a `&Answers` that outlives the whole
    // PAM transaction.
    let answers = unsafe { &*(appdata as *const Answers) };
    let n = num_msg as usize;
    let array = unsafe { libc::calloc(n, std::mem::size_of::<PamResponse>()) } as *mut PamResponse;
    if array.is_null() {
        return PAM_BUF_ERR;
    }
    for i in 0..n {
        // SAFETY: libpam guarantees `msg` points at `num_msg` message pointers.
        let m = unsafe { *msg.add(i) };
        if m.is_null() {
            continue;
        }
        let style = unsafe { (*m).msg_style };
        if style != PAM_PROMPT_ECHO_OFF && style != PAM_PROMPT_ECHO_ON {
            continue;
        }
        let answer = answers.pick(unsafe { (*m).msg });
        // A null `strdup` leaves the response empty, which libpam handles;
        // there is nothing better to do without allocating.
        let dup = unsafe { libc::strdup(answer) };
        unsafe { (*array.add(i)).resp = dup };
    }
    unsafe { *resp = array };
    PAM_SUCCESS
}

// ---------------------------------------------------------------------------
// One PAM transaction
// ---------------------------------------------------------------------------

/// A live `pam_handle_t`, ended on drop.
struct Transaction<'a> {
    pam: &'a Libpam,
    handle: *mut c_void,
    // Kept alive for as long as libpam may call the conversation function.
    _answers: Box<Answers>,
}

impl<'a> Transaction<'a> {
    fn start(
        pam: &'a Libpam,
        confdir: &Path,
        service: &str,
        user: &str,
        answers: Answers,
    ) -> Transaction<'a> {
        let answers = Box::new(answers);
        let conv = PamConv {
            conv: Some(converse),
            appdata_ptr: &*answers as *const Answers as *mut c_void,
        };
        let service = CString::new(service).unwrap();
        let user = CString::new(user).unwrap();
        let confdir = CString::new(confdir.as_os_str().as_encoded_bytes()).unwrap();
        let mut handle: *mut c_void = std::ptr::null_mut();
        let rc = unsafe {
            (pam.start_confdir)(
                service.as_ptr(),
                user.as_ptr(),
                &conv,
                confdir.as_ptr(),
                &mut handle,
            )
        };
        assert_eq!(rc, PAM_SUCCESS, "pam_start_confdir failed with {rc}");
        assert!(!handle.is_null(), "pam_start_confdir returned no handle");
        Transaction {
            pam,
            handle,
            _answers: answers,
        }
    }

    fn authenticate(&self) -> c_int {
        unsafe { (self.pam.authenticate)(self.handle, 0) }
    }

    fn open_session(&self) -> c_int {
        unsafe { (self.pam.open_session)(self.handle, 0) }
    }

    /// libpam runs the password stack twice for one call: once with
    /// `PAM_PRELIM_CHECK` and once with `PAM_UPDATE_AUTHTOK`. An application
    /// is not allowed to pass either flag itself.
    fn chauthtok(&self) -> c_int {
        unsafe { (self.pam.chauthtok)(self.handle, 0) }
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        unsafe { (self.pam.end)(self.handle, PAM_SUCCESS) };
    }
}

// ---------------------------------------------------------------------------
// Prerequisites
// ---------------------------------------------------------------------------

/// The cdylib libpam loads. Built by `make build` into its own target
/// directory; a missing one skips rather than silently passing, and is never
/// built from inside a test (a nested cargo would deadlock on the build lock).
fn module_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target/pam/release/libsecret_manager.so")
}

fn pam_unix_present() -> bool {
    [
        "/usr/lib/security/pam_unix.so",
        "/lib/security/pam_unix.so",
        "/usr/lib64/security/pam_unix.so",
        "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
        "/usr/lib/aarch64-linux-gnu/security/pam_unix.so",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
}

/// `None` (with a printed reason) when this machine cannot run these tests.
fn prerequisites() -> Option<&'static Libpam> {
    static LIB: OnceLock<Result<Libpam, String>> = OnceLock::new();
    // `socket=` is a test-only escape hatch the module ignores when it is
    // root. These tests depend on it being honoured, so being non-root is a
    // precondition, not an accident.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "this suite must not run as root: the module ignores socket= for root"
    );
    let mut reasons = Vec::new();
    let lib = match LIB.get_or_init(load_libpam) {
        Ok(lib) => Some(lib),
        Err(e) => {
            reasons.push(e.clone());
            None
        }
    };
    if !module_path().exists() {
        reasons.push(format!(
            "{} is missing; run `make build` first",
            module_path().display()
        ));
    }
    if !pam_unix_present() {
        reasons.push(
            "pam_unix.so was not found; it is what caches PAM_AUTHTOK for the module to read"
                .to_string(),
        );
    }
    if reasons.is_empty() {
        return lib;
    }
    println!("SKIPPED: {}", reasons.join("; "));
    None
}

/// The name libpam is given for the target user, resolved the same way the
/// module resolves it back into a uid.
fn current_user() -> String {
    let pw = unsafe { libc::getpwuid(libc::geteuid()) };
    assert!(!pw.is_null(), "the current uid has no passwd entry");
    unsafe { CStr::from_ptr((*pw).pw_name) }
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Fixture wiring
// ---------------------------------------------------------------------------

/// The login collection these tests unlock. Separate from the fixture's own
/// `default`, whose `FAST_FOR_TESTS` parameters the module deliberately
/// refuses: `kdf_acceptable_for_login` demands at least 19 MiB and two passes,
/// so a login-grade vault is the only thing this path will touch.
const COLLECTION: &str = "login";
const LOGIN_KDF: KdfParams = KdfParams {
    m_cost_kib: 19 * 1024,
    t_cost: 2,
    p_cost: 1,
};

struct Stack {
    fixture: Fixture,
    _confdir: tempfile::TempDir,
    confdir: PathBuf,
    service: String,
}

impl Stack {
    /// Fixture with a login-grade `login` collection, plus a PAM config
    /// directory whose service file loads the built cdylib by absolute path.
    async fn build(password: &str, service: &str) -> Stack {
        let fixture = Fixture::start().await;
        let vault_dir = fixture.data_dir.path().join("secret-manager");
        Vault::create(
            &vault_dir.join(format!("{COLLECTION}.vault")),
            "Login",
            password.as_bytes(),
            LOGIN_KDF,
        )
        .expect("login vault created");
        let sock = fixture.control_socket();
        let reloaded =
            tokio::task::block_in_place(|| secret_manager::protocol::call(&sock, &Request::Reload))
                .expect("the daemon answers Reload");
        assert!(
            matches!(reloaded, Response::Ok),
            "reload failed: {reloaded:?}"
        );

        let confdir = tempfile::tempdir().unwrap();
        // `auto_start=no`: a test must never reach the branch that runs
        // systemctl. The daemon is already up, so this is only a guard.
        let args = format!(
            "collection={COLLECTION} auto_start=no socket={} vault_dir={}",
            sock.display(),
            vault_dir.display()
        );
        let module = module_path();
        let module = module.display();
        std::fs::write(
            confdir.path().join(service),
            format!(
                "auth     optional pam_unix.so nodelay\n\
                 auth     required {module} {args}\n\
                 session  required {module} {args}\n\
                 password optional pam_unix.so nodelay\n\
                 password required {module} {args}\n"
            ),
        )
        .unwrap();
        let path = confdir.path().to_path_buf();
        Stack {
            fixture,
            _confdir: confdir,
            confdir: path,
            service: service.to_string(),
        }
    }

    fn transaction<'a>(&self, pam: &'a Libpam, user: &str, answers: Answers) -> Transaction<'a> {
        Transaction::start(pam, &self.confdir, &self.service, user, answers)
    }

    fn vault_file(&self) -> PathBuf {
        self.fixture
            .data_dir
            .path()
            .join("secret-manager")
            .join(format!("{COLLECTION}.vault"))
    }

    async fn is_locked(&self) -> bool {
        secret_manager::dbus::state::collection_is_locked(&self.fixture.daemon.state, COLLECTION)
            .await
    }

    async fn relock(&self) {
        secret_manager::dbus::state::with_vault(&self.fixture.daemon.state, COLLECTION, |v| {
            v.lock()
        })
        .await;
    }
}

/// Whether the vault file on disk opens with `password`.
fn vault_opens_with(path: &Path, password: &str) -> bool {
    let mut vault = Vault::open(path).expect("the vault file is readable");
    vault.unlock(password.as_bytes()).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The end-to-end proof that the stash round-trips.
///
/// `authenticate` puts the token libpam cached under `DATA_KEY` with
/// `send_data::<Password>`; `open_session`, a *separate* call into a
/// *separate* `pam_sm_*` symbol later in the same transaction, has to get it
/// back out with `retrieve_data::<Password>`. If those two disagreed — a key
/// mismatch, a type mismatch, data that does not survive between stacks — the
/// session hook would take the `NoPassword` path, the vault would never
/// unlock, and nothing but a syslog line would say so. The assertion is
/// therefore about the daemon, not about the module: the collection is
/// actually unlocked.
///
/// The second `open_session` is the proof that `clear_stashed_password`
/// *lands*. The unit tests prove the module decides to clear on every exit
/// path; only this shows the `send_data` of an empty `Password` replaces the
/// stashed value instead of appending to it. With the collection re-locked and
/// the stash cleared, a second session pass has an empty password and cannot
/// unlock; if the clear had not landed it would unlock a second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_transaction_unlocks_the_collection_and_then_clears_the_stash() {
    let Some(pam) = prerequisites() else { return };
    let password = "login-vault-password";
    let stack = Stack::build(password, "sm-roundtrip").await;
    assert!(stack.is_locked().await, "the collection starts locked");

    let tx = stack.transaction(
        pam,
        &current_user(),
        Answers::new(password, password, password),
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.authenticate()),
        PAM_SUCCESS,
        "the auth stack must see PAM_SUCCESS from the module"
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.open_session()),
        PAM_SUCCESS,
        "the session stack must see PAM_SUCCESS from the module"
    );
    assert!(
        !stack.is_locked().await,
        "the collection is still locked after a full login: the password \
         stashed by pam_sm_authenticate did not reach pam_sm_open_session"
    );

    stack.relock().await;
    assert!(stack.is_locked().await);
    assert_eq!(
        tokio::task::block_in_place(|| tx.open_session()),
        PAM_SUCCESS
    );
    assert!(
        stack.is_locked().await,
        "a second open_session in the same transaction unlocked the vault \
         again: clear_stashed_password did not replace the stashed password"
    );
}

/// The wrong password is derived and sent like any other, and the daemon
/// refuses it. The second half is the control: the same stack, the same
/// transaction shape, the right password, and the collection does unlock —
/// so the refusal above is the daemon's answer and not a stack that never
/// reached it.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_is_refused_and_the_collection_stays_locked() {
    let Some(pam) = prerequisites() else { return };
    let password = "login-vault-password";
    let stack = Stack::build(password, "sm-wrongpw").await;
    let user = current_user();

    let wrong = "not-the-vault-password";
    let tx = stack.transaction(pam, &user, Answers::new(wrong, wrong, wrong));
    assert_eq!(
        tokio::task::block_in_place(|| tx.authenticate()),
        PAM_SUCCESS
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.open_session()),
        PAM_SUCCESS,
        "a refused unlock must never fail the login"
    );
    assert!(
        stack.is_locked().await,
        "the wrong password unlocked the collection"
    );
    drop(tx);

    let tx = stack.transaction(pam, &user, Answers::new(password, password, password));
    assert_eq!(
        tokio::task::block_in_place(|| tx.authenticate()),
        PAM_SUCCESS
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.open_session()),
        PAM_SUCCESS
    );
    assert!(
        !stack.is_locked().await,
        "the control run did not unlock either, so the wrong-password run \
         proves nothing"
    );
}

/// `get_user(None)` returns what the stack holds, and the module uses it.
///
/// Two transactions differing in exactly one thing — the user name given to
/// `pam_start_confdir`. The unresolvable one takes `NoTarget` (there is no
/// uid, so no `/run/user/<uid>` and no home) and leaves the vault locked; the
/// real one unlocks. Nothing else in the two runs differs, so the difference
/// is the value `get_user` handed back.
#[tokio::test(flavor = "multi_thread")]
async fn the_user_name_the_stack_holds_is_the_one_the_module_resolves() {
    let Some(pam) = prerequisites() else { return };
    let password = "login-vault-password";
    let stack = Stack::build(password, "sm-getuser").await;

    let tx = stack.transaction(
        pam,
        "no-such-user-for-pam-stack-test",
        Answers::new(password, password, password),
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.authenticate()),
        PAM_SUCCESS
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.open_session()),
        PAM_SUCCESS,
        "an unresolvable user must not fail the login"
    );
    assert!(
        stack.is_locked().await,
        "a user with no passwd entry still produced an unlock"
    );
    drop(tx);

    let tx = stack.transaction(
        pam,
        &current_user(),
        Answers::new(password, password, password),
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.authenticate()),
        PAM_SUCCESS
    );
    assert_eq!(
        tokio::task::block_in_place(|| tx.open_session()),
        PAM_SUCCESS
    );
    assert!(
        !stack.is_locked().await,
        "the real user did not unlock, so the run above proves nothing"
    );
}

/// `chauthtok` rotates the key, and the `PAM_PRELIM_CHECK` pass does not.
///
/// One `pam_chauthtok` drives the password stack twice — once with
/// `PAM_PRELIM_CHECK`, once with `PAM_UPDATE_AUTHTOK` — and an application is
/// forbidden from passing either flag itself, so the two passes can only be
/// told apart by what the module does on each. libpam sanitizes `PAM_AUTHTOK`
/// and `PAM_OLDAUTHTOK` on entry to the password stack, and on the prelim pass
/// pam_unix sets only `PAM_OLDAUTHTOK`, so on that pass the module never has a
/// complete pair to act on whatever it thinks the flag means. What the flag
/// *does* decide, observably, is which pass the module treats as real: a
/// constant naming the update pass instead (0x2000) makes the module skip the
/// only pass that has both tokens and the vault is never rotated at all.
/// `opens_with(new)` is that assertion.
///
/// [`the_prelim_check_constant_matches_the_platform_header`] covers the value
/// itself, which is the part libpam cannot be made to show.
#[tokio::test(flavor = "multi_thread")]
async fn chauthtok_rotates_the_key() {
    let Some(pam) = prerequisites() else { return };
    let old = "login-vault-password";
    let new = "rotated-vault-password";
    let stack = Stack::build(old, "sm-chauthtok").await;
    let vault = stack.vault_file();
    assert!(vault_opens_with(&vault, old));

    let tx = stack.transaction(pam, &current_user(), Answers::new(old, old, new));
    assert_eq!(
        tokio::task::block_in_place(|| tx.chauthtok()),
        PAM_SUCCESS,
        "the password stack must see PAM_SUCCESS from the module"
    );

    assert!(
        vault_opens_with(&vault, new),
        "the vault does not open with the new password: chauthtok did not \
         rotate the key"
    );
    assert!(
        !vault_opens_with(&vault, old),
        "the vault still opens with the old password"
    );
}

/// The one thing about `PAM_PRELIM_CHECK` libpam cannot be made to
/// demonstrate: that the module's hard-coded copy is the platform's value.
///
/// `pamsm` does not re-export the constant, so `src/pam/mod.rs` spells it out.
/// A wrong value that happens to name no other flag is behaviourally invisible
/// through a live stack — the prelim pass never has both tokens either way —
/// so this reads the number out of the source and out of
/// `<security/pam_modules.h>` and compares them.
#[test]
fn the_prelim_check_constant_matches_the_platform_header() {
    let header = Path::new("/usr/include/security/pam_modules.h");
    if !header.exists() {
        println!(
            "SKIPPED: {} is missing (no libpam headers)",
            header.display()
        );
        return;
    }
    let from_header = std::fs::read_to_string(header)
        .unwrap()
        .lines()
        .find_map(|l| {
            let rest = l.strip_prefix("#define PAM_PRELIM_CHECK")?;
            let v = rest.trim();
            i32::from_str_radix(v.strip_prefix("0x")?, 16).ok()
        })
        .expect("the header defines PAM_PRELIM_CHECK");

    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pam/mod.rs");
    let from_source = std::fs::read_to_string(&source)
        .unwrap()
        .lines()
        .find_map(|l| {
            let rest = l
                .trim()
                .strip_prefix("pub(crate) const PAM_PRELIM_CHECK: i32 = ")?;
            let v = rest.trim_end().strip_suffix(';')?;
            i32::from_str_radix(v.strip_prefix("0x")?, 16).ok()
        })
        .expect("src/pam/mod.rs declares PAM_PRELIM_CHECK as a hex i32");

    assert_eq!(
        from_source, from_header,
        "the module's PAM_PRELIM_CHECK ({from_source:#x}) is not the platform's \
         ({from_header:#x}); the password hook would act on the wrong pass"
    );
}
