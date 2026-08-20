#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

HOME_DIR="/home/rukadopo"
APP="$HOME_DIR/telegram_bridge"
ROOT="$HOME_DIR/telegram_bridge_recovery"
OPS="$HOME_DIR/telegram_bridge_ops"
STATUS="$HOME_DIR/nika_bridge_bootstrap.status"
REPORT_TO="oleksiy.az.09@gmail.com"
TS="$(date '+%Y%m%d_%H%M%S')"
OUT="$ROOT/$TS"
FULL="$OUT/telegram_bridge_PRIVATE_FULL_$TS.tar.gz"
SAFE="$OUT/sanitized"
SAFE_TAR="$OUT/telegram_bridge_SANITIZED_$TS.tar.gz"
REPORT="$OUT/BASELINE_SAFE_REPORT_$TS.txt"
QUAR="$OUT/QUARANTINED_PATHS_$TS.txt"
INCLUDED="$OUT/INCLUDED_PATHS_$TS.txt"

remove_bootstrap_cron() {
  ( crontab -l 2>/dev/null | grep -v 'nika_bridge_bootstrap.sh' || true ) | crontab - 2>/dev/null || true
}

finish() {
  code=$?
  if [ "$code" -eq 0 ]; then
    printf 'SUCCESS\nREPORT=%s\nSAFE_ARCHIVE=%s\nFULL_BACKUP=%s\n' "$REPORT" "$SAFE_TAR" "$FULL" >"$STATUS"
  else
    printf 'FAILED\nEXIT_CODE=%s\n' "$code" >"$STATUS"
  fi
  chmod 600 "$STATUS" 2>/dev/null || true
  remove_bootstrap_cron
  exit "$code"
}
trap finish EXIT

mkdir -p "$OUT" "$SAFE" "$OPS"
chmod 700 "$ROOT" "$OUT" "$SAFE" "$OPS"

[ -d "$APP" ] || { echo "Application not found: $APP" >&2; exit 10; }

# 1. Full PRIVATE production backup. This archive never leaves HOSTiQ automatically.
tar -czf "$FULL" -C "$(dirname "$APP")" "$(basename "$APP")"
chmod 600 "$FULL"
sha256sum "$FULL" >"$FULL.sha256"
chmod 600 "$FULL.sha256"

: >"$QUAR"
: >"$INCLUDED"

is_excluded_path() {
  case "$1" in
    .git/*|var/*|logs/*|log/*|tmp/*|cache/*|__pycache__/*|.pytest_cache/*|.mypy_cache/*|.ruff_cache/*|venv/*|.venv/*) return 0 ;;
    .env|.env.*|*.session|*.session-journal|*.db|*.sqlite|*.sqlite3|*.pem|*.key|*.p12|*.pfx|*.crt|*.log) return 0 ;;
    *token*|*Token*|*TOKEN*|*secret*|*Secret*|*SECRET*|*credential*|*Credential*|*CREDENTIAL*|*cookie*|*Cookie*|*COOKIE*) return 0 ;;
  esac
  return 1
}

looks_secret() {
  local f="$1"
  grep -Eiq 'BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY|[0-9]{8,12}:[A-Za-z0-9_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(api[_-]?(key|hash)|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd|setup[_-]?(key|token|secret))[[:space:]]*[:=][[:space:]]*["'\'' ]?[A-Za-z0-9_./+=:-]{16,}' "$f" 2>/dev/null
}

# 2. Conservative sanitized source snapshot.
while IFS= read -r -d '' f; do
  rel="${f#"$APP"/}"
  if is_excluded_path "$rel"; then
    printf '%s\tPATH_RULE\n' "$rel" >>"$QUAR"
    continue
  fi

  size="$(stat -c '%s' "$f" 2>/dev/null || echo 0)"
  if [ "$size" -gt 2097152 ]; then
    printf '%s\tSIZE_GT_2MB\n' "$rel" >>"$QUAR"
    continue
  fi

  if ! grep -Iq . "$f" 2>/dev/null; then
    printf '%s\tBINARY_OR_NON_TEXT\n' "$rel" >>"$QUAR"
    continue
  fi

  if looks_secret "$f"; then
    printf '%s\tSECRET_PATTERN\n' "$rel" >>"$QUAR"
    continue
  fi

  mkdir -p "$SAFE/$(dirname "$rel")"
  cp -p "$f" "$SAFE/$rel"
  printf '%s\n' "$rel" >>"$INCLUDED"
done < <(find "$APP" -type f -print0)

cat >"$REPORT" <<EOF
TELEGRAM BRIDGE — SANITIZED PRODUCTION BASELINE
Generated: $(date -Is)
Host: $(hostname)
User: $(whoami)
App root: $APP
Private full backup: $FULL
Private backup SHA256: $(cut -d' ' -f1 "$FULL.sha256")
Sanitized included file count: $(wc -l <"$INCLUDED" | tr -d ' ')
Quarantined/excluded file count: $(wc -l <"$QUAR" | tr -d ' ')
Python3: $(command -v python3 2>/dev/null || true)
Python3 version: $(python3 --version 2>&1 || true)
Git in production: $( [ -d "$APP/.git" ] && echo yes || echo no )
Passenger entry file present: $( [ -f "$APP/passenger_wsgi.py" ] && echo yes || echo no )
requirements.txt present: $( [ -f "$APP/requirements.txt" ] && echo yes || echo no )
EOF

{
  echo
  echo "Top-level production entries:"
  find "$APP" -maxdepth 1 -mindepth 1 -printf '%f\t%y\t%s bytes\n' 2>/dev/null | sort || true
  echo
  echo "Quarantined/excluded paths:"
  cat "$QUAR"
} >>"$REPORT"

tar -czf "$SAFE_TAR" -C "$SAFE" .
chmod 600 "$SAFE_TAR" "$REPORT" "$QUAR" "$INCLUDED"
sha256sum "$SAFE_TAR" >"$SAFE_TAR.sha256"
chmod 600 "$SAFE_TAR.sha256"

# 3. Install recurring deploy poller only if the separate audited worker was staged.
if [ -f "$OPS/auto_deploy.sh" ]; then
  chmod 700 "$OPS/auto_deploy.sh"
  CRON_LINE='*/5 * * * * bash /home/rukadopo/telegram_bridge_ops/auto_deploy.sh >/dev/null 2>&1'
  if ! crontab -l 2>/dev/null | grep -Fq '/home/rukadopo/telegram_bridge_ops/auto_deploy.sh'; then
    ( crontab -l 2>/dev/null || true; printf '%s\n' "$CRON_LINE" ) | crontab -
  fi
fi

# 4. Email only the safe report and sanitized archive. Never email the private backup.
SENDMAIL="$(command -v sendmail 2>/dev/null || true)"
if [ -z "$SENDMAIL" ] && [ -x /usr/sbin/sendmail ]; then SENDMAIL=/usr/sbin/sendmail; fi
if [ -n "$SENDMAIL" ] && [ -x "$SENDMAIL" ]; then
  BOUNDARY="NIKA_${TS}_$RANDOM"
  {
    printf 'To: %s\n' "$REPORT_TO"
    printf 'Subject: Telegram Bridge sanitized production baseline %s\n' "$TS"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: multipart/mixed; boundary="%s"\n\n' "$BOUNDARY"

    printf -- '--%s\n' "$BOUNDARY"
    printf 'Content-Type: text/plain; charset=UTF-8\n'
    printf 'Content-Transfer-Encoding: 8bit\n\n'
    cat "$REPORT"
    printf '\n'

    if [ "$(stat -c '%s' "$SAFE_TAR")" -le 18874368 ]; then
      printf -- '--%s\n' "$BOUNDARY"
      printf 'Content-Type: application/gzip; name="telegram_bridge_SANITIZED_%s.tar.gz"\n' "$TS"
      printf 'Content-Disposition: attachment; filename="telegram_bridge_SANITIZED_%s.tar.gz"\n' "$TS"
      printf 'Content-Transfer-Encoding: base64\n\n'
      base64 -w 76 "$SAFE_TAR"
      printf '\n'
    else
      printf '\nSanitized archive is larger than 18 MiB and remains server-side at: %s\n' "$SAFE_TAR"
    fi

    printf -- '--%s--\n' "$BOUNDARY"
  } | "$SENDMAIL" -t
else
  printf '\nWARNING: sendmail unavailable. Sanitized archive remains server-side at %s\n' "$SAFE_TAR" >>"$REPORT"
fi
