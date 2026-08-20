#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

HOME_DIR="/home/rukadopo"
APP="$HOME_DIR/telegram_bridge"
ROOT="$HOME_DIR/telegram_bridge_recovery_v2"
REPORT_TO="oleksiy.az.09@gmail.com"
TS="$(date '+%Y%m%d_%H%M%S')"
OUT="$ROOT/$TS"
SAFE="$OUT/sanitized"
SAFE_TAR="$OUT/telegram_bridge_SANITIZED_V2_$TS.tar.gz"
REPORT="$OUT/BASELINE_SAFE_REPORT_V2_$TS.txt"
INCLUDED="$OUT/INCLUDED_PATHS_V2_$TS.txt"
QUAR="$OUT/QUARANTINED_PATHS_V2_$TS.txt"
STATUS="$HOME_DIR/nika_bridge_recovery_v2.status"

mkdir -p "$OUT" "$SAFE"
chmod 700 "$ROOT" "$OUT" "$SAFE"
[ -d "$APP" ] || { printf 'FAILED\nAPP_NOT_FOUND\n' >"$STATUS"; exit 10; }

python3 - "$APP" "$SAFE" "$INCLUDED" "$QUAR" <<'PY'
from __future__ import print_function
import os, re, shutil, sys

app, safe, included_path, quar_path = sys.argv[1:5]

EXCLUDED_DIRS = {'.git','var','logs','log','tmp','cache','__pycache__','.pytest_cache','.mypy_cache','.ruff_cache','venv','.venv'}
EXCLUDED_EXTS = {'.session','.session-journal','.db','.sqlite','.sqlite3','.pem','.key','.p12','.pfx','.crt','.log'}
SECRET_NAME_WORDS = ('token','secret','credential','cookie')
MAX_SIZE = 2 * 1024 * 1024

secret_patterns = [
    re.compile(r'BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY', re.I),
    re.compile(r'\b\d{8,12}:[A-Za-z0-9_-]{30,}\b'),
    re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
    re.compile(r'''(?ix)
        (?:api[_-]?(?:key|hash)|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd|setup[_-]?(?:key|token|secret))
        \s*[:=]\s*["']?[A-Za-z0-9_./+=:-]{16,}
    ''')
]

included = []
quar = []

for root, dirs, files in os.walk(app):
    rel_root = os.path.relpath(root, app)
    dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
    for name in files:
        path = os.path.join(root, name)
        rel = os.path.normpath(os.path.join(rel_root, name)) if rel_root != '.' else name
        low = name.lower()
        ext = os.path.splitext(low)[1]

        if low == '.env' or low.startswith('.env.') or ext in EXCLUDED_EXTS or any(w in low for w in SECRET_NAME_WORDS):
            quar.append((rel, 'PATH_RULE'))
            continue

        try:
            size = os.path.getsize(path)
        except OSError:
            quar.append((rel, 'STAT_ERROR'))
            continue
        if size > MAX_SIZE:
            quar.append((rel, 'SIZE_GT_2MB'))
            continue

        try:
            data = open(path, 'rb').read()
        except Exception:
            quar.append((rel, 'READ_ERROR'))
            continue

        if b'\x00' in data:
            quar.append((rel, 'BINARY_NUL'))
            continue

        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            quar.append((rel, 'NON_UTF8'))
            continue

        if any(p.search(text) for p in secret_patterns):
            quar.append((rel, 'SECRET_PATTERN'))
            continue

        dest = os.path.join(safe, rel)
        parent = os.path.dirname(dest)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(dest, 'wb') as f:
            f.write(data)
        included.append(rel)

with open(included_path, 'w') as f:
    for rel in sorted(included):
        f.write(rel + '\n')

with open(quar_path, 'w') as f:
    for rel, reason in sorted(quar):
        f.write('%s\t%s\n' % (rel, reason))
PY

cat >"$REPORT" <<EOF
TELEGRAM BRIDGE — SANITIZED PRODUCTION BASELINE V2
Generated: $(date -Is)
Host: $(hostname)
User: $(whoami)
App root: $APP
Sanitized included file count: $(wc -l <"$INCLUDED" | tr -d ' ')
Quarantined/excluded file count: $(wc -l <"$QUAR" | tr -d ' ')
Python3: $(command -v python3 2>/dev/null || true)
Python3 version: $(python3 --version 2>&1 || true)
Passenger entry file present: $( [ -f "$APP/passenger_wsgi.py" ] && echo yes || echo no )
requirements.txt present: $( [ -f "$APP/requirements.txt" ] && echo yes || echo no )
EOF

{
  echo
  echo "Included paths:"
  cat "$INCLUDED"
  echo
  echo "Quarantined/excluded paths:"
  cat "$QUAR"
} >>"$REPORT"

tar -czf "$SAFE_TAR" -C "$SAFE" .
chmod 600 "$SAFE_TAR" "$REPORT" "$INCLUDED" "$QUAR"
sha256sum "$SAFE_TAR" >"$SAFE_TAR.sha256"
chmod 600 "$SAFE_TAR.sha256"

COUNT="$(wc -l <"$INCLUDED" | tr -d ' ')"
if [ "$COUNT" -eq 0 ]; then
  printf 'FAILED\nNO_INCLUDED_FILES\nREPORT=%s\n' "$REPORT" >"$STATUS"
  chmod 600 "$STATUS"
  exit 20
fi

SENDMAIL="$(command -v sendmail 2>/dev/null || true)"
if [ -z "$SENDMAIL" ] && [ -x /usr/sbin/sendmail ]; then SENDMAIL=/usr/sbin/sendmail; fi

if [ -n "$SENDMAIL" ] && [ -x "$SENDMAIL" ]; then
  BOUNDARY="NIKA_V2_${TS}_$RANDOM"
  {
    printf 'To: %s\n' "$REPORT_TO"
    printf 'Subject: Telegram Bridge sanitized production baseline V2 %s\n' "$TS"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: multipart/mixed; boundary="%s"\n\n' "$BOUNDARY"
    printf -- '--%s\n' "$BOUNDARY"
    printf 'Content-Type: text/plain; charset=UTF-8\n'
    printf 'Content-Transfer-Encoding: 8bit\n\n'
    cat "$REPORT"
    printf '\n'
    if [ "$(stat -c '%s' "$SAFE_TAR")" -le 18874368 ]; then
      printf -- '--%s\n' "$BOUNDARY"
      printf 'Content-Type: application/gzip; name="telegram_bridge_SANITIZED_V2_%s.tar.gz"\n' "$TS"
      printf 'Content-Disposition: attachment; filename="telegram_bridge_SANITIZED_V2_%s.tar.gz"\n' "$TS"
      printf 'Content-Transfer-Encoding: base64\n\n'
      base64 -w 76 "$SAFE_TAR"
      printf '\n'
    else
      printf '\nArchive >18MiB; kept server-side at: %s\n' "$SAFE_TAR"
    fi
    printf -- '--%s--\n' "$BOUNDARY"
  } | "$SENDMAIL" -t
fi

printf 'SUCCESS\nSAFE_ARCHIVE=%s\nREPORT=%s\nINCLUDED=%s\n' "$SAFE_TAR" "$REPORT" "$COUNT" >"$STATUS"
chmod 600 "$STATUS"
