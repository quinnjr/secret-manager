#!/bin/sh
# Scripted stand-in for `gpg` in tests. Only the invocations `sm gpg`
# makes are understood; anything else exits 2.
#   FAKE_GPG_COLONS  file whose contents are printed for
#                    `gpg -K --with-keygrip --with-colons` (a keyring with
#                    no secret keys prints nothing and exits 0)
#   FAKE_GPG_STATE   directory holding `preset-<keygrip>` markers written
#                    by fake-gpg-connect-agent.sh; `--batch --clearsign`
#                    succeeds only when at least one marker exists, which is
#                    what makes the enroll roundtrip causal rather than canned
# When `--homedir <dir>` is passed (the daemon always passes it
# explicitly, since its environment cannot be trusted for GNUPGHOME),
# both the colons file and the state directory resolve under <dir>
# instead — unless the FAKE_GPG_* variables are set, which win so
# CLI-path tests (whose subprocesses inherit a login environment)
# stay hermetic.
#   FAKE_GPG_K_FAIL      when "1", `gpg -K` exits non-zero the way a broken
#                        keyring does, so discovery-failure paths are reachable
#   FAKE_GPG_TESTSIGN_FAIL
#                        when "1", `--batch --clearsign` always fails, so the
#                        enroll-verification failure branch is reachable even
#                        after a successful preset
#   FAKE_GPG_TESTSIGN_GRIP
#                        when set, `--batch --clearsign` (invoked with
#                        `--local-user`) succeeds only if that grip was
#                        preset, proving the verifier signs with the enrolled
#                        key rather than the ring default
#   FAKE_GPG_LOG     file that receives every argv line
if [ -n "$FAKE_GPG_LOG" ]; then printf '%s\n' "$*" >> "$FAKE_GPG_LOG"; fi
homedir=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--homedir" ]; then homedir="$arg"; fi
  prev="$arg"
done
if [ -n "$FAKE_GPG_COLONS" ] || [ -n "$FAKE_GPG_STATE" ]; then
  colons="$FAKE_GPG_COLONS"
  state="$FAKE_GPG_STATE"
elif [ -n "$homedir" ]; then
  colons="$homedir/colons"
  state="$homedir"
else
  colons=""
  state=""
fi
case "$*" in
  *"-K --with-keygrip --with-colons"*)
    if [ "$FAKE_GPG_K_FAIL" = "1" ]; then
      echo "gpg: keyring failed" >&2
      exit 2
    fi
    if [ "$FAKE_GPG_K_FAIL" = "quiet" ]; then
      exit 2
    fi
    if [ -n "$colons" ] && [ -f "$colons" ]; then
      cat "$colons"
    fi
    exit 0
    ;;
  *"--batch --clearsign"*)
    cat > /dev/null
    if [ "$FAKE_GPG_TESTSIGN_FAIL" = "1" ]; then
      echo "gpg: signing failed: No secret key" >&2
      exit 2
    fi
    if [ -n "$FAKE_GPG_TESTSIGN_GRIP" ]; then
      # The verifier must pin the enrolled key: without --local-user the
      # proof could come from any cached default, so its absence fails.
      case "$*" in
        *"--local-user"*) ;;
        *)
          echo "gpg: signing failed: No secret key" >&2
          exit 2
          ;;
      esac
      if [ -n "$state" ] && [ -f "$state/preset-$FAKE_GPG_TESTSIGN_GRIP" ]; then
        printf -- '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\ntest\n'
        exit 0
      fi
      echo "gpg: signing failed: No secret key" >&2
      exit 2
    fi
    if [ -n "$state" ] && ls "$state"/preset-* >/dev/null 2>&1; then
      printf -- '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\ntest\n'
      exit 0
    fi
    echo "gpg: signing failed: No secret key" >&2
    exit 2
    ;;
esac
echo "fake-gpg: unexpected invocation: $*" >&2
exit 2
