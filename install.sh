#!/bin/sh
# One-line installer for a fresh machine:
#   curl -fsSL https://raw.githubusercontent.com/OWNER/ssh-club/main/install.sh | sudo sh
set -eu

REPO="${CLUB_REPO:-OWNER/ssh-club}"

case "$(uname -m)" in
  aarch64|arm64) arch=aarch64 ;;
  x86_64|amd64)  arch=x86_64 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

# A binary next to this script (or in the cwd) wins over downloading.
if [ -x ./club ]; then
  exec ./club install "$@"
fi

url="https://github.com/$REPO/releases/latest/download/club-linux-$arch"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
echo "downloading $url"
curl -fsSL "$url" -o "$tmp"
chmod +x "$tmp"
"$tmp" install "$@"
