#!/usr/bin/env bash
# Downloads Xray-core for Linux into the given directory (default ./xray).
# XRAY_VERSION: "latest" (default) or a tag such as v26.10.21.
set -euo pipefail

VERSION="${XRAY_VERSION:-latest}"
DEST="${1:-./xray}"

case "$(uname -m)" in
  x86_64|amd64)  ASSET="Xray-linux-64.zip" ;;
  aarch64|arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/XTLS/Xray-core/releases/latest/download/${ASSET}"
else
  URL="https://github.com/XTLS/Xray-core/releases/download/${VERSION}/${ASSET}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$DEST"

echo "Downloading $URL"
curl -fsSL --retry 5 --retry-delay 3 -o "$TMP/xray.zip" "$URL"

# Best-effort integrity check against the published .dgst file.
if curl -fsSL --retry 3 -o "$TMP/xray.zip.dgst" "${URL}.dgst" 2>/dev/null; then
  want="$(grep -iE '^SHA2?-?256' "$TMP/xray.zip.dgst" | head -n1 | sed 's/.*= *//' | tr -d '[:space:]' | tr 'A-F' 'a-f' || true)"
  have="$(sha256sum "$TMP/xray.zip" | cut -d' ' -f1)"
  if [ -n "$want" ] && [ "$want" != "$have" ]; then
    echo "Checksum mismatch for $ASSET" >&2
    exit 1
  fi
fi

if command -v unzip >/dev/null 2>&1; then
  unzip -q -o "$TMP/xray.zip" -d "$DEST"
else
  python3 -m zipfile -e "$TMP/xray.zip" "$DEST"
fi
chmod +x "$DEST/xray"
"$DEST/xray" version | head -n 1
