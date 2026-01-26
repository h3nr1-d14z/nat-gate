#!/bin/bash
set -e

REPO="h3nr1-d14z/nat-gate"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="nat-gate"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    error "nat-gate only supports Linux. Current OS: $(uname -s)"
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        BINARY_SUFFIX="linux-x86_64"
        ;;
    aarch64|arm64)
        BINARY_SUFFIX="linux-aarch64"
        ;;
    *)
        error "Unsupported architecture: $ARCH"
        ;;
esac

info "Detected architecture: $ARCH"

# Check for curl or wget
if command -v curl &> /dev/null; then
    DOWNLOADER="curl"
elif command -v wget &> /dev/null; then
    DOWNLOADER="wget"
else
    error "Please install curl or wget to continue"
fi

# Get latest release version
info "Fetching latest release..."
if [[ "$DOWNLOADER" == "curl" ]]; then
    LATEST_RELEASE=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
else
    LATEST_RELEASE=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
fi

if [[ -z "$LATEST_RELEASE" ]]; then
    error "Could not determine latest release. Please check https://github.com/${REPO}/releases"
fi

info "Latest release: $LATEST_RELEASE"

# Construct download URL
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/${BINARY_NAME}-${BINARY_SUFFIX}"

# Create temp directory
TMP_DIR=$(mktemp -d)
TMP_FILE="${TMP_DIR}/${BINARY_NAME}"
trap "rm -rf $TMP_DIR" EXIT

# Download binary
info "Downloading ${BINARY_NAME} from ${DOWNLOAD_URL}..."
if [[ "$DOWNLOADER" == "curl" ]]; then
    curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
else
    wget -q "$DOWNLOAD_URL" -O "$TMP_FILE"
fi

# Verify download
if [[ ! -f "$TMP_FILE" ]] || [[ ! -s "$TMP_FILE" ]]; then
    error "Download failed or file is empty"
fi

# Make executable
chmod +x "$TMP_FILE"

# Install to /usr/local/bin (requires sudo)
info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
if [[ -w "$INSTALL_DIR" ]]; then
    mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
else
    sudo mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
fi

# Verify installation
if command -v nat-gate &> /dev/null; then
    VERSION=$(nat-gate --version)
    success "nat-gate installed successfully!"
    echo ""
    echo "  Version: $VERSION"
    echo "  Location: ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""
    echo "Get started:"
    echo "  sudo nat-gate init    # Initialize system"
    echo "  sudo nat-gate --help  # Show available commands"
else
    error "Installation completed but nat-gate is not in PATH"
fi
