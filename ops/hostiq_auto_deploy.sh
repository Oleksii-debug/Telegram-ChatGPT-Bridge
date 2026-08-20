#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

HOME_DIR="/home/rukadopo"
APP="$HOME_DIR/telegram_bridge"
OPS="$HOME_DIR/telegram_bridge_ops"
REPO="$HOME_DIR/telegram_bridge_release_repo"
REPO_URL="https://github.com/Oleksii-debug/Telegram-ChatGPT-Bridge.git"
LOCK="$OPS/deploy.lock"
LOG="$OPS/deploy.log"
STATE="$OPS/last_deployed_sha"
BACKUPS="$HOME_DIR/telegram_bridge_deploy_backups"

mkdir -p "$OPS" "$BACKUPS"
touch "$LOG"
exec 9>"$LOCK"
flock -n 9 || exit 0

say(){ printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG"; }

if [ ! -d "$REPO/.git" ]; then
  rm -rf "$REPO"
  git clone --no-tags "$REPO_URL" "$REPO" >>"$LOG" 2>&1 || { say "clone failed"; exit 0; }
fi

git -C "$REPO" fetch --prune --no-tags origin main >>"$LOG" 2>&1 || { say "fetch failed"; exit 0; }
SHA="$(git -C "$REPO" rev-parse origin/main 2>/dev/null || true)"
[ -n "$SHA" ] || { say "cannot resolve origin/main"; exit 0; }

# Fail closed: no deployment until audited main explicitly enables it.
MARKER="$(git -C "$REPO" show "$SHA:ops/ENABLE_HOSTIQ_AUTO_DEPLOY" 2>/dev/null || true)"
[ "$(printf '%s' "$MARKER" | tr -d '\r\n ')" = "ENABLED" ] || { say "not armed: $SHA"; exit 0; }

git -C "$REPO" cat-file -e "$SHA:ops/hostiq_deploy.conf" 2>/dev/null || { say "armed but config missing"; exit 0; }
git -C "$REPO" cat-file -e "$SHA:ops/hostiq_preserve_paths.txt" 2>/dev/null || { say "armed but preserve list missing"; exit 0; }

LAST="$(cat "$STATE" 2>/dev/null || true)"
[ "$SHA" != "$LAST" ] || exit 0

CFG_TMP="$(mktemp)"
PRES_TMP="$(mktemp)"
STAGE="$(mktemp -d "$HOME_DIR/.tg_stage.XXXXXX")"
ROLLBACK="$(mktemp -d "$HOME_DIR/.tg_rollback.XXXXXX")"
cleanup(){ rm -f "$CFG_TMP" "$PRES_TMP"; rm -rf "$STAGE" "$ROLLBACK"; }
trap cleanup EXIT

git -C "$REPO" show "$SHA:ops/hostiq_deploy.conf" >"$CFG_TMP"
git -C "$REPO" show "$SHA:ops/hostiq_preserve_paths.txt" >"$PRES_TMP"

HEALTH_URL=""
VENV_PYTHON=""
ALLOW_PIP_INSTALL="0"
while IFS='=' read -r k v; do
  k="$(printf '%s' "$k" | tr -d '[:space:]')"
  v="${v%$'\r'}"
  case "$k" in
    HEALTH_URL) HEALTH_URL="$v" ;;
    VENV_PYTHON) VENV_PYTHON="$v" ;;
    ALLOW_PIP_INSTALL) ALLOW_PIP_INSTALL="$v" ;;
  esac
done <"$CFG_TMP"

[ -n "$HEALTH_URL" ] || { say "config missing HEALTH_URL"; exit 0; }
[ -n "$VENV_PYTHON" ] || VENV_PYTHON="$(command -v python3 || true)"
[ -x "$VENV_PYTHON" ] || { say "python unavailable: $VENV_PYTHON"; exit 0; }
command -v rsync >/dev/null 2>&1 || { say "rsync unavailable"; exit 0; }
command -v curl >/dev/null 2>&1 || { say "curl unavailable"; exit 0; }

# Build isolated staging tree from exact main SHA.
git -C "$REPO" archive "$SHA" | tar -x -C "$STAGE"

# Preserve only explicitly audited relative production paths.
while IFS= read -r rel || [ -n "$rel" ]; do
  rel="${rel%$'\r'}"
  [ -z "$rel" ] && continue
  case "$rel" in \#*) continue ;; esac
  case "$rel" in /*|*".."*) say "invalid preserve path: $rel"; exit 0 ;; esac
  if [ -e "$APP/$rel" ]; then
    mkdir -p "$STAGE/$(dirname "$rel")"
    cp -a "$APP/$rel" "$STAGE/$rel"
  fi
done <"$PRES_TMP"

# Preflight before touching production.
"$VENV_PYTHON" -m compileall -q "$STAGE" >>"$LOG" 2>&1 || { say "compileall failed for $SHA"; exit 0; }
if [ -d "$STAGE/tests" ] && "$VENV_PYTHON" -c 'import pytest' >/dev/null 2>&1; then
  timeout 180 "$VENV_PYTHON" -m pytest -q "$STAGE/tests" >>"$LOG" 2>&1 || { say "pytest failed for $SHA"; exit 0; }
fi

if [ "$ALLOW_PIP_INSTALL" = "1" ] && [ -f "$STAGE/requirements.txt" ]; then
  "$VENV_PYTHON" -m pip install -r "$STAGE/requirements.txt" >>"$LOG" 2>&1 || { say "pip install failed for $SHA"; exit 0; }
fi

STAMP="$(date '+%Y%m%d_%H%M%S')"
BACKUP="$BACKUPS/predeploy_${STAMP}_${SHA}.tar.gz"
tar -czf "$BACKUP" -C "$(dirname "$APP")" "$(basename "$APP")" >>"$LOG" 2>&1 || { say "backup failed"; exit 0; }
sha256sum "$BACKUP" >"$BACKUP.sha256"

rsync -a "$APP/" "$ROLLBACK/"

if ! rsync -a --delete "$STAGE/" "$APP/" >>"$LOG" 2>&1; then
  say "deploy rsync failed; rolling back"
  rsync -a --delete "$ROLLBACK/" "$APP/" >>"$LOG" 2>&1 || true
  mkdir -p "$APP/tmp"; touch "$APP/tmp/restart.txt"
  exit 0
fi

mkdir -p "$APP/tmp"
touch "$APP/tmp/restart.txt"
sleep 4

if ! curl -fsS --max-time 20 "$HEALTH_URL" >/dev/null; then
  say "health failed; rolling back $SHA"
  rsync -a --delete "$ROLLBACK/" "$APP/" >>"$LOG" 2>&1 || true
  mkdir -p "$APP/tmp"; touch "$APP/tmp/restart.txt"
  sleep 4
  curl -fsS --max-time 20 "$HEALTH_URL" >/dev/null \
    && say "rollback health OK" \
    || say "CRITICAL: rollback health also failed"
  exit 0
fi

printf '%s\n' "$SHA" >"$STATE"
say "DEPLOYED $SHA backup=$BACKUP"
