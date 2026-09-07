#!/bin/sh
# Scripted Assuan pinentry for tests.
#   FAKE_PIN      value answered to GETPIN (Assuan-escaped); unset => cancel
#   FAKE_CONFIRM  "yes" => CONFIRM succeeds; anything else => cancel
#   FAKE_LOG      file that receives every command line
#   FAKE_DELAY    seconds to hang before answering GETPIN or CONFIRM (tests
#                 that race a client-side abort/Dismiss, or a state change,
#                 against a dialog that is still on screen)
#
# When FAKE_LOG is set, "${FAKE_LOG}.timing" also receives "START <pid>
# <epoch-nanos>" when a GETPIN is received and "END <pid> <epoch-nanos>"
# right after it is answered, so tests can prove dialogs never overlap
# without relying on wall-clock timing thresholds.
echo "OK Pleased to meet you"
while IFS= read -r line; do
  if [ -n "$FAKE_LOG" ]; then printf '%s\n' "$line" >> "$FAKE_LOG"; fi
  case "$line" in
    GETPIN*)
      if [ -n "$FAKE_LOG" ]; then
        printf 'START %s %s\n' "$$" "$(date +%s%N)" >> "${FAKE_LOG}.timing"
      fi
      if [ -n "$FAKE_DELAY" ]; then sleep "$FAKE_DELAY"; fi
      if [ -n "$FAKE_PIN" ]; then
        printf 'D %s\n' "$FAKE_PIN"
        echo "OK"
      else
        echo "ERR 83886179 Operation cancelled <Pinentry>"
      fi
      if [ -n "$FAKE_LOG" ]; then
        printf 'END %s %s\n' "$$" "$(date +%s%N)" >> "${FAKE_LOG}.timing"
      fi
      ;;
    CONFIRM*)
      if [ -n "$FAKE_DELAY" ]; then sleep "$FAKE_DELAY"; fi
      if [ "$FAKE_CONFIRM" = "yes" ]; then echo "OK"; else echo "ERR 83886179 Operation cancelled <Pinentry>"; fi
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
