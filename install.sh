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
INSTALL_WEB="${JABALI_WEB:-yes}"   # set JABALI_WEB=no to skip web dashboard

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
        apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 ;;
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

    # Stop and disable services
    for svc in "$SERVICE_NAME" jabali-security-web; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
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
            pkg_install git python3 python3-venv python3-pip file coreutils \
                nftables libnginx-mod-http-modsecurity modsecurity-crs
            ;;
        dnf)
            pkg_install git python3 python3-pip file coreutils \
                nftables mod_security mod_security_crs
            ;;
        yum)
            pkg_install git python3 python3-pip file coreutils \
                nftables mod_security mod_security_crs
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

    # -- Install ClamAV if not present --
    if ! command -v clamd &>/dev/null && ! command -v clamdscan &>/dev/null; then
        echo "Installing ClamAV (optional scanning backend)..."
        case "$pkg_mgr" in
            apt) pkg_install clamav-daemon clamav-freshclam ;;
            dnf) pkg_install clamav clamd clamav-update ;;
            yum) pkg_install clamav clamd clamav-update ;;
        esac
        echo "ClamAV installed."
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
    mkdir -p "$INSTALL_DIR"/lib/{watcher,scanner,bruteforce,waf,proactive,cleanup,threat_intel,webshield,ufw}
    if [ "$INSTALL_WEB" = "yes" ]; then
        mkdir -p "$INSTALL_DIR"/web/{templates,static/css,static/js}
    fi

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
    cp "$tmp_dir"/lib/ufw/*.py "$INSTALL_DIR/lib/ufw/"
    cp "$tmp_dir"/api/*.py "$INSTALL_DIR/api/"
    mkdir -p "$INSTALL_DIR/api/routes"
    cp "$tmp_dir"/api/routes/*.py "$INSTALL_DIR/api/routes/"
    if [ "$INSTALL_WEB" = "yes" ]; then
        cp "$tmp_dir"/web/*.py "$INSTALL_DIR/web/"
        cp "$tmp_dir"/web/templates/*.html "$INSTALL_DIR/web/templates/"
        cp -r "$tmp_dir"/web/static/* "$INSTALL_DIR/web/static/"
    fi
    cp "$tmp_dir"/rules/*.yar "$INSTALL_DIR/rules/"
    cp "$tmp_dir"/etc/jabali-security.conf.example "$INSTALL_DIR/etc/"
    cp "$tmp_dir"/etc/jabali-security.service "$INSTALL_DIR/etc/"
    cp "$tmp_dir"/etc/jabali-security-web.service "$INSTALL_DIR/etc/"
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

    # -- Auto-detect and configure WAF/CRS paths --
    CRS_DIR=""
    for d in /usr/share/modsecurity-crs/rules /etc/modsecurity/crs /usr/share/modsecurity-crs; do
        if [ -d "$d" ] && ls "$d"/*.conf &>/dev/null; then
            CRS_DIR="$d"
            break
        fi
    done
    if [ -n "$CRS_DIR" ]; then
        echo "OWASP CRS found at $CRS_DIR"
        if ! grep -q "^WAF_RULES_DIR=" "$CONFIG_DIR/jabali-security.conf" 2>/dev/null; then
            echo "WAF_RULES_DIR=\"$CRS_DIR\"" >> "$CONFIG_DIR/jabali-security.conf"
        else
            sed -i "s|^WAF_RULES_DIR=.*|WAF_RULES_DIR=\"$CRS_DIR\"|" "$CONFIG_DIR/jabali-security.conf"
        fi
    fi

    # -- Enable features with detected dependencies (on fresh install) --
    if command -v nft &>/dev/null || command -v iptables &>/dev/null; then
        sed -i 's|^BRUTEFORCE_ENABLED="no"|BRUTEFORCE_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf"
        echo "Brute-force protection enabled."
    fi
    if [ -n "$CRS_DIR" ]; then
        sed -i 's|^WAF_ENABLED="no"|WAF_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf"
        echo "WAF enabled."
    fi
    # Enable proactive defense + process monitor by default
    # PHP hardening left disabled — hosting panels (Jabali Panel, cPanel) manage this
    sed -i 's|^PROACTIVE_ENABLED="no"|PROACTIVE_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    sed -i 's|^PROCESS_KILL_ENABLED="no"|PROCESS_KILL_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    sed -i 's|^THREAT_INTEL_ENABLED="no"|THREAT_INTEL_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    sed -i 's|^WEBSHIELD_ENABLED="no"|WEBSHIELD_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    sed -i 's|^CLEANUP_ENABLED="no"|CLEANUP_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null

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
        local pip_pkgs="pydantic>=2.0 yara-x>=0.11 click>=8.0 aiohttp>=3.9 pyyaml>=6.0 aiosqlite>=0.20"
        if [ "$INSTALL_WEB" = "yes" ]; then
            pip_pkgs="$pip_pkgs flask>=3.0 waitress>=3.0"
        fi
        if command -v uv &>/dev/null; then
            # shellcheck disable=SC2086
            uv pip install --python "$_venv_dir/bin/python" $pip_pkgs 2>&1 | tail -1
        # shellcheck disable=SC2086
        elif "$_venv_dir/bin/pip" install --quiet $pip_pkgs; then
            echo "Dependencies installed."
        else
            red "WARNING: failed to install dependencies. Check network and re-run."
        fi
    fi

    # -- Install systemd services --
    cp "$INSTALL_DIR/etc/jabali-security.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true

    if [ "$INSTALL_WEB" = "yes" ]; then
        cp "$INSTALL_DIR/etc/jabali-security-web.service" /etc/systemd/system/
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable jabali-security-web 2>/dev/null || true
        systemctl restart jabali-security-web 2>/dev/null || true
        # Open web dashboard port in UFW if active
        if command -v ufw &>/dev/null && ufw status | grep -q "^Status: active"; then
            local web_port
            web_port=$(grep "^WEB_PORT=" "$CONFIG_DIR/jabali-security.conf" 2>/dev/null | cut -d'"' -f2)
            web_port="${web_port:-8443}"
            ufw allow "$web_port/tcp" comment "Jabali Security Dashboard" 2>/dev/null || true
            echo "UFW: opened port $web_port/tcp for web dashboard."
        fi
    else
        # Stop web service if previously installed
        systemctl stop jabali-security-web 2>/dev/null || true
        systemctl disable jabali-security-web 2>/dev/null || true
        echo "Web dashboard skipped (JABALI_WEB=no)."
    fi

    # Read the API key for display
    local api_key
    api_key=$(grep "^API_KEY=" "$CONFIG_DIR/jabali-security.conf" 2>/dev/null | cut -d'"' -f2)

    echo ""
    green "Jabali Security installed successfully!"
    echo ""
    echo "  Daemon:    systemctl status $SERVICE_NAME"
    if [ "$INSTALL_WEB" = "yes" ]; then
        echo "  Dashboard: http://0.0.0.0:8443"
    fi
    echo "  API Key:   $api_key"
    echo "  Config:    $CONFIG_DIR/jabali-security.conf"
    echo "  CLI:       jabali-security --help"
    echo "  Logs:      journalctl -u $SERVICE_NAME -f"
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
        echo ""
        echo "Environment variables:"
        echo "  JABALI_WEB=no   Skip web dashboard installation"
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
