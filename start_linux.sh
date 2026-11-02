#!/usr/bin/env bash
# ==============================================================================
# AI Application Security Auditor - Linux Launcher
# Syncs source from the (slow) VirtualBox shared folder to a native Linux
# directory, installs npm packages there (fast, symlinks allowed), and runs.
#
# Usage:
#   ./start_linux.sh            # sync + install (if needed) + npm run dev
#   ./start_linux.sh install    # sync + force npm install, don't start
#   ./start_linux.sh sync       # only sync source files
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APPSEC_APP_DIR:-$HOME/appsec-platform}"
MODE="${1:-run}"

mkdir -p "$APP_DIR"

echo -e "${BLUE}[*] Syncing source: $SRC_DIR -> $APP_DIR${NC}"
EXCLUDES=(--exclude=node_modules --exclude=venv --exclude=.venv --exclude=dist --exclude=.git)
if command -v rsync &> /dev/null; then
  rsync -a --delete "${EXCLUDES[@]}" --exclude=.npm-installed.stamp "$SRC_DIR/" "$APP_DIR/"
else
  tar -C "$SRC_DIR" "${EXCLUDES[@]}" -cf - . | tar -C "$APP_DIR" -xf -
fi

# Strip any Windows CRLF line endings from shell scripts
find "$APP_DIR" -maxdepth 2 -name "*.sh" -not -path "*/node_modules/*" -exec sed -i 's/\r$//' {} +

cd "$APP_DIR"

[ "$MODE" = "sync" ] && { echo -e "${GREEN}[✓] Sync complete.${NC}"; exit 0; }

# Reinstall only when package.json changed or node_modules missing
STAMP="$APP_DIR/.npm-installed.stamp"
if [ "$MODE" = "install" ] || [ ! -d node_modules ] || [ ! -f "$STAMP" ] || [ package.json -nt "$STAMP" ]; then
  echo -e "${BLUE}[*] Installing npm packages in $APP_DIR (native Linux filesystem)...${NC}"
  npm install --no-audit --no-fund
  touch "$STAMP"
  echo -e "${GREEN}[✓] npm packages installed.${NC}"
else
  echo -e "${GREEN}[✓] npm packages up to date.${NC}"
fi

[ "$MODE" = "install" ] && exit 0

echo -e "${GREEN}[*] Starting platform from $APP_DIR ...${NC}"
echo -e "${YELLOW}    (Edit code on Windows, then re-run ./start_linux.sh to sync changes)${NC}"
exec npm run dev

