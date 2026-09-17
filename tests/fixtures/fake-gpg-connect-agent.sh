#!/bin/sh
# Scripted stand-in for `gpg-connect-agent` in tests.
#   FAKE_GPG_STATE       directory holding `preset-<keygrip>` markers
#   GNUPGHOME            fallback state directory when FAKE_GPG_STATE is
#                        unset: the daemon always sets it explicitly to the
#                        configured homedir, since its own environment cannot
#                        be trusted for it
#   FAKE_GPG_PRESET_FAIL when "1", PRESET_PASSPHRASE is refused the way a
#                        gpg-agent without `allow-preset-passphrase` refuses
#                        it, so the hint path is reachable in tests. A
#                        `fail-preset` file in the state directory does the
#                        same without process-global environment, which the
#                        daemon's in-process tests must not mutate.
#   FAKE_GPG_LOG         file that receives every command line
STATE="${FAKE_GPG_STATE:-$GNUPGHOME}"
echo "OK fake gpg agent"
while IFS= read -r line; do
  if [ -n "$FAKE_GPG_LOG" ]; then printf '%s\n' "$line" >> "$FAKE_GPG_LOG"; fi
  case "$line" in
    PRESET_PASSPHRASE*)
      set -- $line
      if [ "$FAKE_GPG_PRESET_FAIL" = "1" ] || { [ -n "$STATE" ] && [ -f "$STATE/fail-preset" ]; }; then
        echo "ERR 67109144 IPC parameter error <GPG Agent> - preset passphrase not allowed"
      elif [ -n "$STATE" ] && [ -n "$2" ]; then
        touch "$STATE/preset-$2"
        echo "OK"
      else
        echo "ERR 67109144 IPC parameter error <GPG Agent>"
      fi
      ;;
    CLEAR_PASSPHRASE*)
      set -- $line
      if [ -n "$STATE" ] && [ -n "$2" ]; then
        rm -f "$STATE/preset-$2"
      fi
      echo "OK"
      ;;
    BYE*)
      echo "OK closing connection"
      exit 0
      ;;
    *)
      echo "OK"
      ;;
  esac
done
