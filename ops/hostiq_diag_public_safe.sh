#!/usr/bin/env bash
set -u
umask 077

HOME_DIR="/home/rukadopo"
PUBLIC_DIR="$HOME_DIR/public_html"
OUT="$PUBLIC_DIR/telegram_bridge_diag_20260820_1410_a7c4e9f2.txt"

mkdir -p "$PUBLIC_DIR"

# Stop the repeating FORCE cron and remove this diagnostic cron after it starts.
(
  crontab -l 2>/dev/null \
    | grep -v 'nika_force_v2_marker' \
    | grep -v 'nika_diag_safe_marker' \
    || true
) | crontab -

# Kill only lingering processes that belong to the FORCE cron marker.
# The diagnostic command itself carries nika_diag_safe_marker and is excluded.
PIDS="$(ps -eo pid=,args= 2>/dev/null \
  | grep 'nika_force_v2_marker' \
  | grep -v 'nika_diag_safe_marker' \
  | grep -v 'grep ' \
  | awk '{print $1}' \
  || true)"

for PID in $PIDS; do
  kill "$PID" 2>/dev/null || true
done

emit_file() {
  NAME="$1"
  PATHNAME="$HOME_DIR/$NAME"
  echo "===== $NAME ====="
  if [ ! -f "$PATHNAME" ]; then
    echo "MISSING"
    return
  fi
  stat -c 'SIZE=%s MTIME=%y' "$PATHNAME" 2>/dev/null || true
  grep -Eai 'FORCE_START|FORCE_END|CURL_RC=|RUN_RC=|ERROR=|STATUS_FILE_NOT_FOUND|SUCCESS|FAILED|NO_INCLUDED_FILES|SAFE_ARCHIVE=|REPORT=|INCLUDED=|syntax error|not found|No such file|permission denied|timed out|timeout|curl:|sendmail' "$PATHNAME" 2>/dev/null \
    | tail -n 120 \
    || true
  echo
}

{
  echo "TELEGRAM_BRIDGE_SAFE_DIAGNOSTIC"
  echo "GENERATED=$(date -Is)"
  echo "HOST=$(hostname 2>/dev/null || true)"
  echo "USER=$(whoami 2>/dev/null || true)"
  echo
  emit_file "nika_force_v2.log"
  emit_file "nika_force_v2_cron_outer.log"
  emit_file "nika_bridge_recovery_v2.status"
  emit_file "nika_bridge_recover_v2_cron.log"
  emit_file "nika_bridge_bootstrap.status"
  emit_file "nika_bridge_launcher_cron.log"
  echo "===== CRON AFTER CLEANUP ====="
  crontab -l 2>/dev/null \
    | grep -E 'telegram_bridge|nika_' \
    | sed -E 's#https?://[^ ]+#<URL>#g' \
    | tail -n 50 \
    || true
} >"$OUT"

chmod 644 "$OUT"

# Remove the temporary public diagnostic automatically after 15 minutes.
(
  sleep 900
  rm -f "$OUT"
) >/dev/null 2>&1 &

exit 0
