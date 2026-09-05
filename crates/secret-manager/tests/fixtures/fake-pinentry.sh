#!/bin/sh
# Scripted Assuan pinentry for tests.
#   FAKE_PIN      value answered to GETPIN (Assuan-escaped); unset => cancel
#   FAKE_CONFIRM  "yes" => CONFIRM succeeds; anything else => cancel
#   FAKE_LOG      file that receives every command line
echo "OK Pleased to meet you"
while IFS= read -r line; do
  if [ -n "$FAKE_LOG" ]; then printf '%s\n' "$line" >> "$FAKE_LOG"; fi
  case "$line" in
    GETPIN*)
      if [ -n "$FAKE_PIN" ]; then
        printf 'D %s\n' "$FAKE_PIN"
        echo "OK"
      else
        echo "ERR 83886179 Operation cancelled <Pinentry>"
      fi
      ;;
    CONFIRM*)
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
