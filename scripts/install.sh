#!/usr/bin/env sh
set -eu

REPO="KuroSystems/BurpSuitePro_TUI"
BIN="proxima-tui"
INSTALL_DIR="${PROXIMA_INSTALL_DIR:-}"

os="$(uname -s)"
arch="$(uname -m)"
case "$os:$arch" in
  Linux:x86_64) artifact="proxima-tui-x86_64-unknown-linux-musl" ;;
  Darwin:x86_64) artifact="proxima-tui-x86_64-apple-darwin" ;;
  Darwin:arm64) artifact="proxima-tui-aarch64-apple-darwin" ;;
  MINGW*:x86_64|MSYS*:x86_64|CYGWIN*:x86_64) artifact="proxima-tui-x86_64-pc-windows-gnu.exe" ; BIN="proxima-tui.exe" ;;
  *) echo "Unsupported platform: $os $arch" >&2; exit 1 ;;
esac

if [ -z "$INSTALL_DIR" ]; then
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR=/usr/local/bin
  else
    INSTALL_DIR="$HOME/.local/bin"
  fi
fi
mkdir -p "$INSTALL_DIR"

tag="${PROXIMA_VERSION:-latest}"
if [ "$tag" = "latest" ]; then
  url="https://github.com/$REPO/releases/latest/download/$artifact"
else
  url="https://github.com/$REPO/releases/download/$tag/$artifact"
fi

tmp="$(mktemp)"
echo "Downloading $url"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmp"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$url" -O "$tmp"
else
  echo "curl or wget is required" >&2
  exit 1
fi
chmod +x "$tmp"
mv "$tmp" "$INSTALL_DIR/$BIN"
echo "Installed $BIN to $INSTALL_DIR/$BIN"

if [ -n "${PROXIMA_CA_CERT:-}" ] && [ -f "$PROXIMA_CA_CERT" ]; then
  case "$os" in
    Linux)
      if command -v sudo >/dev/null 2>&1 && command -v update-ca-certificates >/dev/null 2>&1; then
        sudo cp "$PROXIMA_CA_CERT" /usr/local/share/ca-certificates/proxima-tui-ca.crt
        sudo update-ca-certificates
        echo "Installed CA certificate into Linux system trust store"
      fi
      ;;
    Darwin)
      sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$PROXIMA_CA_CERT" || true
      ;;
  esac
fi

echo "Run '$BIN', start the proxy from Settings, then import certs/proxima-ca.pem into your browser/OS trust store if not installed automatically."
