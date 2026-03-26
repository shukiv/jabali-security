#!/bin/bash
# Jabali Security — install / uninstall script
set -euo pipefail

INSTALL_DIR="/usr/local/jabali-security"
CONFIG_DIR="/etc/jabali-security"
LOG_DIR="/var/log/jabali-security"
DATA_DIR="/var/lib/jabali-security"
QUARANTINE_DIR="/var/security/quarantine"
SERVICE_NAME="jabali-security"
SYSCTL_CONF="/etc/sysctl.d/99-jabali-security.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

    # -- Install Python 3.12+ if missing --
    if ! command -v python3 &>/dev/null || [ "$(python3 -c 'import sys; print(sys.version_info >= (3,12))' 2>/dev/null)" != "True" ]; then
        echo "Installing Python 3.12+..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq
            apt-get install -y -qq python3 python3-venv python3-pip >/dev/null
        elif command -v dnf &>/dev/null; then
            dnf install -y -q python3 python3-pip
        elif command -v yum &>/dev/null; then
            yum install -y -q python3 python3-pip
        else
            red "Error: cannot detect package manager. Install Python 3.12+ manually."
            exit 1
        fi

        if ! command -v python3 &>/dev/null; then
            red "Error: Python 3 installation failed."
            exit 1
        fi
        echo "Python $(python3 --version) installed."
    fi

    # -- Copy application files --
    mkdir -p "$INSTALL_DIR"/{daemon,lib/watcher,lib/scanner,api,rules,etc,bin}

    cp "$SCRIPT_DIR"/daemon/*.py "$INSTALL_DIR/daemon/"
    cp "$SCRIPT_DIR"/lib/*.py "$INSTALL_DIR/lib/"
    cp "$SCRIPT_DIR"/lib/watcher/*.py "$INSTALL_DIR/lib/watcher/"
    cp "$SCRIPT_DIR"/lib/scanner/*.py "$INSTALL_DIR/lib/scanner/"
    cp "$SCRIPT_DIR"/api/*.py "$INSTALL_DIR/api/"
    cp "$SCRIPT_DIR"/rules/*.yar "$INSTALL_DIR/rules/"
    cp "$SCRIPT_DIR"/etc/jabali-security.conf.example "$INSTALL_DIR/etc/"
    cp "$SCRIPT_DIR"/etc/jabali-security.service "$INSTALL_DIR/etc/"
    cp "$SCRIPT_DIR"/bin/jabali-security "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/jabali-security"

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
            red "WARNING: failed to create venv. Install python3-venv and re-run."
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
