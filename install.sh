#!/bin/bash
# Jabali Security — install / uninstall script
# Usage:
#   curl -fsSL https://git.linux-hosting.co.il/shukivaknin/jabali-security/raw/branch/master/install.sh | sudo bash
#   sudo bash install.sh --uninstall
set -euo pipefail

REPO_URL="https://git.linux-hosting.co.il/shukivaknin/jabali-security.git"
INSTALL_DIR="/usr/local/jabali-security"
CONFIG_DIR="/etc/jabali-security"
LOG_DIR="/var/log/jabali-security"
DATA_DIR="/var/lib/jabali-security"
QUARANTINE_DIR="/var/security/quarantine"
SERVICE_NAME="jabali-security"
SYSCTL_CONF="/etc/sysctl.d/99-jabali-security.conf"

# ── Helpers ────────────────────────────────────────────────────────────────

red()   { echo -e "\033[0;31m$*\033[0m"; }
green() { echo -e "\033[0;32m$*\033[0m"; }
bold()  { echo -e "\033[1m$*\033[0m"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        red "Error: this script must be run as root."
        exit 1
    fi
}

detect_os() {
    # Detect distro from /etc/os-release (standard on systemd-based distros)
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-}"
        OS_NAME="${PRETTY_NAME:-$OS_ID}"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_VERSION="$(grep -oE '[0-9]+' /etc/redhat-release | head -1)"
        OS_NAME="$(cat /etc/redhat-release)"
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
        OS_VERSION="$(cat /etc/debian_version)"
        OS_NAME="Debian $OS_VERSION"
    else
        OS_ID="unknown"
        OS_VERSION=""
        OS_NAME="Unknown Linux"
    fi
    export OS_ID OS_VERSION OS_NAME
}

detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo "unknown"
    fi
}

pkg_install() {
    local pkg_mgr
    pkg_mgr="$(detect_pkg_manager)"
    case "$pkg_mgr" in
        apt) apt-get update -qq && apt-get install -y -qq "$@" >/dev/null ;;
        dnf) dnf install -y -q "$@" ;;
        yum) yum install -y -q "$@" ;;
        *)
            red "Error: cannot detect package manager (apt/dnf/yum). Install manually: $*"
            exit 1
            ;;
    esac
}

# ── Uninstall ──────────────────────────────────────────────────────────────

do_uninstall() {
    require_root
    bold "Uninstalling Jabali Security..."

    # Stop and disable service
    if systemctl is-active "$SERVICE_NAME" &>/dev/null; then
        echo "Stopping $SERVICE_NAME..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi
    if systemctl is-enabled "$SERVICE_NAME" &>/dev/null; then
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    fi
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true

    # Remove installation
    echo "Removing $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"

    # Remove CLI symlink
    rm -f /usr/local/bin/jabali-security

    # Remove config, data, logs, quarantine
    echo "Removing config ($CONFIG_DIR)..."
    rm -rf "$CONFIG_DIR"
    echo "Removing data ($DATA_DIR)..."
    rm -rf "$DATA_DIR"
    echo "Removing logs ($LOG_DIR)..."
    rm -rf "$LOG_DIR"
    echo "Removing quarantine ($QUARANTINE_DIR)..."
    rm -rf "$QUARANTINE_DIR"

    # Remove sysctl config
    if [ -f "$SYSCTL_CONF" ]; then
        rm -f "$SYSCTL_CONF"
        sysctl --system &>/dev/null || true
    fi

    green "Jabali Security has been completely removed."
}

# ── Install ────────────────────────────────────────────────────────────────

do_install() {
    require_root
    bold "Installing Jabali Security..."

    # -- Detect OS --
    detect_os
    echo "Detected OS: $OS_NAME (id=$OS_ID, version=${OS_VERSION:-n/a})"

    # -- Install system dependencies --
    echo "Installing system dependencies..."
    local pkg_mgr
    pkg_mgr="$(detect_pkg_manager)"

    case "$pkg_mgr" in
        apt)
            pkg_install git python3 python3-venv python3-pip file coreutils
            ;;
        dnf)
            pkg_install git python3 python3-pip file coreutils
            ;;
        yum)
            pkg_install git python3 python3-pip file coreutils
            ;;
        *)
            red "Error: cannot detect package manager (apt/dnf/yum)."
            exit 1
            ;;
    esac

    # -- Verify Python 3.12+ --
    if ! command -v python3 &>/dev/null; then
        red "Error: Python 3 installation failed."
        exit 1
    fi
    if [ "$(python3 -c 'import sys; print(sys.version_info >= (3,12))' 2>/dev/null)" != "True" ]; then
        red "Error: Python 3.12+ is required. Found: $(python3 --version 2>&1)"
        red "Please install Python 3.12 or later manually."
        exit 1
    fi
    echo "Python $(python3 --version 2>&1) — OK"

    # -- Optional: install ClamAV if not present --
    if ! command -v clamd &>/dev/null && ! command -v clamdscan &>/dev/null; then
        echo ""
        echo "ClamAV is not installed. It provides an optional scanning backend."
        if [ -t 0 ]; then
            read -r -p "Install ClamAV? (y/N) " install_clamav
        elif [ -e /dev/tty ]; then
            read -r -p "Install ClamAV? (y/N) " install_clamav < /dev/tty
        else
            install_clamav="n"
            echo "(non-interactive mode — skipping ClamAV)"
        fi
        if [ "${install_clamav,,}" = "y" ]; then
            echo "Installing ClamAV..."
            case "$pkg_mgr" in
                apt) pkg_install clamav-daemon clamav-freshclam ;;
                dnf) pkg_install clamav clamd clamav-update ;;
                yum) pkg_install clamav clamd clamav-update ;;
            esac
            echo "ClamAV installed."
        else
            echo "Skipping ClamAV (can be installed later)."
        fi
    else
        echo "ClamAV detected — OK"
    fi

    # -- Clone repo to temp dir --
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    echo "Cloning repository..."
    git clone --depth 1 --quiet "$REPO_URL" "$tmp_dir"

    # -- Copy application files --
    mkdir -p "$INSTALL_DIR"/{daemon,api,rules,etc,bin}
    mkdir -p "$INSTALL_DIR"/lib/{watcher,scanner,bruteforce,waf,proactive,cleanup,threat_intel,webshield}
    mkdir -p "$INSTALL_DIR"/web/{templates,static/css,static/js}

    cp "$tmp_dir"/daemon/*.py "$INSTALL_DIR/daemon/"
    cp "$tmp_dir"/lib/*.py "$INSTALL_DIR/lib/"
    cp "$tmp_dir"/lib/watcher/*.py "$INSTALL_DIR/lib/watcher/"
    cp "$tmp_dir"/lib/scanner/*.py "$INSTALL_DIR/lib/scanner/"
    cp "$tmp_dir"/lib/bruteforce/*.py "$INSTALL_DIR/lib/bruteforce/"
    cp "$tmp_dir"/lib/waf/*.py "$INSTALL_DIR/lib/waf/"
    cp "$tmp_dir"/lib/proactive/*.py "$INSTALL_DIR/lib/proactive/"
    cp "$tmp_dir"/lib/cleanup/*.py "$INSTALL_DIR/lib/cleanup/"
    cp "$tmp_dir"/lib/threat_intel/*.py "$INSTALL_DIR/lib/threat_intel/"
    cp "$tmp_dir"/lib/webshield/*.py "$INSTALL_DIR/lib/webshield/"
    cp "$tmp_dir"/api/*.py "$INSTALL_DIR/api/"
    cp "$tmp_dir"/web/*.py "$INSTALL_DIR/web/"
    cp "$tmp_dir"/web/templates/*.html "$INSTALL_DIR/web/templates/"
    cp -r "$tmp_dir"/web/static/* "$INSTALL_DIR/web/static/"
    cp "$tmp_dir"/rules/*.yar "$INSTALL_DIR/rules/"
    cp "$tmp_dir"/etc/jabali-security.conf.example "$INSTALL_DIR/etc/"
    cp "$tmp_dir"/etc/jabali-security.service "$INSTALL_DIR/etc/"
    cp -r "$tmp_dir"/etc/webshield "$INSTALL_DIR/etc/" 2>/dev/null || true
    cp "$tmp_dir"/bin/jabali-security "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/jabali-security"

    # Clean up temp clone
    rm -rf "$tmp_dir"

    # -- CLI symlink --
    ln -sf "$INSTALL_DIR/bin/jabali-security" /usr/local/bin/jabali-security

    # -- Create directories --
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    mkdir -p "$QUARANTINE_DIR"
    chmod 700 "$QUARANTINE_DIR"

    # -- Copy config (only if not exists) --
    if [ ! -f "$CONFIG_DIR/jabali-security.conf" ]; then
        cp "$INSTALL_DIR/etc/jabali-security.conf.example" "$CONFIG_DIR/jabali-security.conf"
        chmod 600 "$CONFIG_DIR/jabali-security.conf"
        echo "Config created at $CONFIG_DIR/jabali-security.conf"
    else
        echo "Config already exists, keeping current."
    fi

    # -- Generate API_KEY if not set --
    if ! grep -q "^API_KEY=" "$CONFIG_DIR/jabali-security.conf" 2>/dev/null || \
       grep -q '^API_KEY=""' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null; then
        api_key="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 43)"
        if grep -q "^API_KEY=" "$CONFIG_DIR/jabali-security.conf"; then
            sed -i "s|^API_KEY=.*|API_KEY=\"${api_key}\"|" "$CONFIG_DIR/jabali-security.conf"
        else
            echo "API_KEY=\"${api_key}\"" >> "$CONFIG_DIR/jabali-security.conf"
        fi
        chmod 600 "$CONFIG_DIR/jabali-security.conf"
        echo "API key generated."
    fi

    # -- Set inotify watch limit --
    current_watches=$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo 0)
    if [ "$current_watches" -lt 524288 ]; then
        echo "fs.inotify.max_user_watches=524288" > "$SYSCTL_CONF"
        sysctl -p "$SYSCTL_CONF" 2>/dev/null || true
        echo "inotify watch limit raised to 524288."
    fi

    # -- Create Python venv and install dependencies --
    _venv_dir="$INSTALL_DIR/venv"
    if [ ! -d "$_venv_dir" ] || [ ! -f "$_venv_dir/bin/python" ]; then
        echo "Creating Python venv..."
        if ! python3 -m venv "$_venv_dir" 2>/dev/null; then
            echo "Installing python3-venv..."
            pkg_install python3-venv
            python3 -m venv "$_venv_dir"
        fi
    fi

    if [ -f "$_venv_dir/bin/pip" ]; then
        echo "Installing Python dependencies..."
        if command -v uv &>/dev/null; then
            uv pip install --python "$_venv_dir/bin/python" \
                "pydantic>=2.0" "yara-x>=0.11" "click>=8.0" "aiohttp>=3.9" "pyyaml>=6.0" "aiosqlite>=0.20" \
                2>&1 | tail -1
        elif "$_venv_dir/bin/pip" install --quiet \
            "pydantic>=2.0" "yara-x>=0.11" "click>=8.0" "aiohttp>=3.9" "pyyaml>=6.0" "aiosqlite>=0.20"; then
            echo "Dependencies installed."
        else
            red "WARNING: failed to install dependencies. Check network and re-run."
        fi
    fi

    # -- Install systemd service --
    cp "$INSTALL_DIR/etc/jabali-security.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl start "$SERVICE_NAME" 2>/dev/null || true

    echo ""
    green "Jabali Security installed successfully!"
    echo ""
    echo "  Service:  systemctl status $SERVICE_NAME"
    echo "  Config:   $CONFIG_DIR/jabali-security.conf"
    echo "  CLI:      jabali-security --help"
    echo "  Logs:     journalctl -u $SERVICE_NAME -f"
}

# ── Main ───────────────────────────────────────────────────────────────────

case "${1:-}" in
    --uninstall)
        do_uninstall
        ;;
    --help|-h)
        echo "Usage: $0 [--uninstall]"
        echo ""
        echo "  (no args)     Install Jabali Security"
        echo "  --uninstall   Completely remove Jabali Security (config, data, logs)"
        ;;
    "")
        do_install
        ;;
    *)
        red "Unknown option: $1"
        echo "Usage: $0 [--uninstall]"
        exit 1
        ;;
esac
