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

red()    { echo -e "\033[0;31m$*\033[0m"; }
green()  { echo -e "\033[0;32m$*\033[0m"; }
yellow() { echo -e "\033[0;33m$*\033[0m"; }
cyan()   { echo -e "\033[0;36m$*\033[0m"; }
bold()   { echo -e "\033[1m$*\033[0m"; }

# Spinner — runs in background, killed by stop_spinner
_spinner_pid=""
_spinner_flag=""

start_spinner() {
    local label="$1"
    _spinner_flag=$(mktemp /tmp/.jabali-sec-spinner-XXXXXX)
    (
        local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
        local n=${#frames[@]} i=0
        tput civis 2>/dev/null || true
        while [ -f "$_spinner_flag" ]; do
            printf "\r\033[0;36m[%s]\033[0m %s " "${frames[i % n]}" "$label" >&2
            i=$((i + 1))
            sleep 0.08
        done
    ) &
    _spinner_pid=$!
}

stop_spinner() {
    local success="${1:-true}"
    local label="$2"
    rm -f "$_spinner_flag" 2>/dev/null
    if [ -n "$_spinner_pid" ]; then
        wait "$_spinner_pid" 2>/dev/null || true
        _spinner_pid=""
    fi
    tput cnorm 2>/dev/null || true
    if [ "$success" = "true" ]; then
        printf "\r\033[0;32m[✓]\033[0m %s\n" "$label" >&2
    else
        printf "\r\033[0;31m[✗]\033[0m %s\n" "$label" >&2
    fi
}

# Run a command with spinner
run_with_spinner() {
    local label="$1"; shift
    start_spinner "$label"
    local log_file
    log_file=$(mktemp /tmp/jabali-sec-XXXXXX.log)
    local rc=0
    "$@" > "$log_file" 2>&1 || rc=$?
    if [ $rc -eq 0 ]; then
        stop_spinner true "$label"
    else
        stop_spinner false "$label"
        yellow "    Last output:"
        tail -5 "$log_file" | sed 's/^/    /'
    fi
    rm -f "$log_file"
    return $rc
}

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
    for svc in "$SERVICE_NAME"; do
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

section() { echo ""; bold "=== $* ==="; }
done_ok() { green "[✓] $*"; }

do_install() {
    require_root
    echo ""
    bold "╔════════════════════════════════════════════════════════════╗"
    bold "║          Jabali Security — Installer                      ║"
    bold "╚════════════════════════════════════════════════════════════╝"
    echo ""

    # -- Detect OS --
    section "Detecting System"
    detect_os
    echo "  OS: $OS_NAME (id=$OS_ID, version=${OS_VERSION:-n/a})"

    section "Installing System Dependencies"
    local pkg_mgr
    pkg_mgr="$(detect_pkg_manager)"

    case "$pkg_mgr" in
        apt)
            run_with_spinner "Installing system packages (apt)" \
                pkg_install git python3 python3-venv python3-pip file coreutils \
                nftables ufw libnginx-mod-http-modsecurity modsecurity-crs
            ;;
        dnf)
            run_with_spinner "Installing system packages (dnf)" \
                pkg_install git python3 python3-pip file coreutils \
                nftables ufw mod_security mod_security_crs
            ;;
        yum)
            run_with_spinner "Installing system packages (yum)" \
                pkg_install git python3 python3-pip file coreutils \
                nftables ufw mod_security mod_security_crs
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
    done_ok "Python $(python3 --version 2>&1)"

    if ! command -v clamd &>/dev/null && ! command -v clamdscan &>/dev/null; then
        case "$pkg_mgr" in
            apt) run_with_spinner "Installing ClamAV" pkg_install clamav-daemon clamav-freshclam ;;
            dnf) run_with_spinner "Installing ClamAV" pkg_install clamav clamd clamav-update ;;
            yum) run_with_spinner "Installing ClamAV" pkg_install clamav clamd clamav-update ;;
        esac
    else
        green "[✓] ClamAV already installed"
    fi

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    run_with_spinner "Downloading Jabali Security" git clone --depth 1 --quiet "$REPO_URL" "$tmp_dir"

    section "Installing Application Files"
    mkdir -p "$INSTALL_DIR"/{daemon,api,rules,etc,bin}
    mkdir -p "$INSTALL_DIR"/lib/{watcher,scanner,bruteforce,waf,proactive,cleanup,threat_intel,webshield,ufw}
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
    mkdir -p "$INSTALL_DIR/lib/sshjail"
    cp "$tmp_dir"/lib/sshjail/*.py "$INSTALL_DIR/lib/sshjail/"
    cp "$tmp_dir"/api/*.py "$INSTALL_DIR/api/"
    mkdir -p "$INSTALL_DIR/api/routes"
    cp "$tmp_dir"/api/routes/*.py "$INSTALL_DIR/api/routes/"
    cp "$tmp_dir"/rules/*.yar "$INSTALL_DIR/rules/"
    cp "$tmp_dir"/etc/jabali-security.conf.example "$INSTALL_DIR/etc/"
    cp "$tmp_dir"/etc/jabali-security.service "$INSTALL_DIR/etc/"
    cp -r "$tmp_dir"/etc/webshield "$INSTALL_DIR/etc/" 2>/dev/null || true
    cp "$tmp_dir"/bin/jabali-security "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/jabali-security"

    done_ok "Application files installed"

    # -- Jabali Panel integration (Filament plugin) --
    JABALI_PANEL_DIR="/var/www/jabali"
    if [ -d "$JABALI_PANEL_DIR/app/Filament" ]; then
        section "Installing Jabali Panel Plugin"
        mkdir -p "$JABALI_PANEL_DIR/app/JabaliSecurity/Pages"
        mkdir -p "$JABALI_PANEL_DIR/app/JabaliSecurity/Widgets"
        mkdir -p "$JABALI_PANEL_DIR/app/JabaliSecurity/views"
        cp "$tmp_dir"/panel/JabaliSecurityPlugin.php "$JABALI_PANEL_DIR/app/JabaliSecurity/"
        cp "$tmp_dir"/panel/JabaliSecurityClient.php "$JABALI_PANEL_DIR/app/JabaliSecurity/"
        cp "$tmp_dir"/panel/Pages/*.php "$JABALI_PANEL_DIR/app/JabaliSecurity/Pages/"
        cp "$tmp_dir"/panel/Widgets/*.php "$JABALI_PANEL_DIR/app/JabaliSecurity/Widgets/"
        cp "$tmp_dir"/panel/views/*.blade.php "$JABALI_PANEL_DIR/app/JabaliSecurity/views/"

        # Register plugin in AdminPanelProvider if not already registered
        PROVIDER="$JABALI_PANEL_DIR/app/Providers/Filament/AdminPanelProvider.php"
        if [ -f "$PROVIDER" ] && ! grep -q "JabaliSecurityPlugin" "$PROVIDER" 2>/dev/null; then
            python3 -c "
p='$PROVIDER'
with open(p) as f: c=f.read()
if 'JabaliSecurityPlugin' not in c and '->middleware([' in c:
    b='''            ->plugins(array_filter([
                class_exists(\\\App\\\JabaliSecurity\\\JabaliSecurityPlugin::class)
                    ? \\\App\\\JabaliSecurity\\\JabaliSecurityPlugin::make()
                    : null,
            ]))
'''
    c=c.replace('            ->middleware([',b+'            ->middleware([',1)
    with open(p,'w') as f: f.write(c)
    print('  Security plugin registered in AdminPanelProvider.')
"
        fi

        done_ok "Jabali Panel plugin installed"
    fi

    # Clean up temp clone
    rm -rf "$tmp_dir"

    # -- CLI symlink --
    ln -sf "$INSTALL_DIR/bin/jabali-security" /usr/local/bin/jabali-security

    section "Configuring Directories & Permissions"
    mkdir -p "$CONFIG_DIR"
    if id www-data &>/dev/null; then
        chown root:www-data "$CONFIG_DIR"
        chmod 750 "$CONFIG_DIR"
    else
        chmod 700 "$CONFIG_DIR"
    fi
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    mkdir -p "$QUARANTINE_DIR"
    chmod 700 "$QUARANTINE_DIR"

    done_ok "Directories created"

    section "Configuring Security Daemon"
    # Always ensure correct permissions (even on reinstall)
    if id www-data &>/dev/null; then
        chown root:www-data "$CONFIG_DIR" 2>/dev/null
        chmod 750 "$CONFIG_DIR" 2>/dev/null
    fi

    if [ ! -f "$CONFIG_DIR/jabali-security.conf" ]; then
        cp "$INSTALL_DIR/etc/jabali-security.conf.example" "$CONFIG_DIR/jabali-security.conf"
        if id www-data &>/dev/null; then
            chown root:www-data "$CONFIG_DIR/jabali-security.conf"
            chmod 640 "$CONFIG_DIR/jabali-security.conf"
        else
            chmod 600 "$CONFIG_DIR/jabali-security.conf"
        fi
        echo "  Config: $CONFIG_DIR/jabali-security.conf"
    else
        echo "  Config already exists, keeping current."
        # Fix permissions on existing config
        if id www-data &>/dev/null; then
            chown root:www-data "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
            chmod 640 "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
        fi
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
        if id www-data &>/dev/null; then
            chown root:www-data "$CONFIG_DIR/jabali-security.conf"
            chmod 640 "$CONFIG_DIR/jabali-security.conf"
        else
            chmod 600 "$CONFIG_DIR/jabali-security.conf"
        fi
        echo "  API key generated."
    fi

    # -- Set Unix socket path if not already present --
    if ! grep -q "^API_SOCKET=" "$CONFIG_DIR/jabali-security.conf" 2>/dev/null; then
        echo 'API_SOCKET="/run/jabali-security/jabali-security.sock"' >> "$CONFIG_DIR/jabali-security.conf"
    fi
    # Disable TCP by default (Unix socket is primary)
    sed -i 's|^API_BIND="127.0.0.1"|API_BIND=""|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null

    done_ok "Daemon configured"

    section "Configuring WAF (ModSecurity)"
    CRS_DIR=""
    for d in /usr/share/modsecurity-crs/rules /etc/modsecurity/crs /usr/share/modsecurity-crs; do
        if [ -d "$d" ] && ls "$d"/*.conf &>/dev/null; then
            CRS_DIR="$d"
            break
        fi
    done
    if [ -n "$CRS_DIR" ]; then
        echo "  OWASP CRS found at $CRS_DIR"
        if ! grep -q "^WAF_RULES_DIR=" "$CONFIG_DIR/jabali-security.conf" 2>/dev/null; then
            echo "WAF_RULES_DIR=\"$CRS_DIR\"" >> "$CONFIG_DIR/jabali-security.conf"
        else
            sed -i "s|^WAF_RULES_DIR=.*|WAF_RULES_DIR=\"$CRS_DIR\"|" "$CONFIG_DIR/jabali-security.conf"
        fi
    fi

    if [ -f /etc/nginx/modsecurity.conf ]; then
        sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity.conf
        echo "  ModSecurity set to blocking mode."

        sed -i 's|^WAF_AUDIT_LOG=.*|WAF_AUDIT_LOG="/var/log/nginx/modsec_audit.log"|' "$CONFIG_DIR/jabali-security.conf"

        if [ -n "$CRS_DIR" ] && [ -f /etc/nginx/modsecurity_includes.conf ]; then
            CRS_SETUP=""
            for f in /etc/modsecurity/crs/crs-setup.conf /usr/share/modsecurity-crs/crs-setup.conf; do
                if [ -f "$f" ]; then CRS_SETUP="$f"; break; fi
            done
            if [ -n "$CRS_SETUP" ]; then
                cat > /etc/nginx/modsecurity_includes.conf << MODSECEOF
include modsecurity.conf
include $CRS_SETUP
include $CRS_DIR/*.conf
MODSECEOF
                echo "  CRS rules configured for nginx."
            fi
        fi

        if ! grep -q "modsecurity on" /etc/nginx/nginx.conf 2>/dev/null; then
            sed -i '/http {/a\\tmodsecurity on;\n\tmodsecurity_rules_file /etc/nginx/modsecurity_includes.conf;' /etc/nginx/nginx.conf
            echo "  ModSecurity enabled in nginx."
        fi

        # Enable WAF per-site in the nginx include
        WAF_INCLUDE_DIR="/etc/nginx/jabali/includes"
        mkdir -p "$WAF_INCLUDE_DIR"
        cat > "$WAF_INCLUDE_DIR/waf.conf" << 'WAFEOF'
# Managed by Jabali Security
modsecurity on;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'" always;
WAFEOF
        echo "  WAF per-site include ...... enabled"

        if nginx -t 2>/dev/null; then
            systemctl reload nginx 2>/dev/null || true
            done_ok "WAF configured (ModSecurity + OWASP CRS)"
        else
            red "  WARNING: nginx config test failed after ModSecurity setup."
        fi
    else
        echo "  ModSecurity not found, skipping WAF setup."
    fi

    section "Enabling Protection Modules"
    if command -v nft &>/dev/null || command -v iptables &>/dev/null; then
        sed -i 's|^BRUTEFORCE_ENABLED="no"|BRUTEFORCE_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf"
        echo "  Brute-force protection .... enabled"
    fi
    if [ -n "$CRS_DIR" ]; then
        sed -i 's|^WAF_ENABLED="no"|WAF_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf"
        echo "  WAF (ModSecurity) ........ enabled"
    fi
    sed -i 's|^PROCESS_KILL_ENABLED="no"|PROCESS_KILL_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    echo "  Process Killer ........... enabled"
    sed -i 's|^THREAT_INTEL_ENABLED="no"|THREAT_INTEL_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    echo "  Threat Intelligence ...... enabled"
    sed -i 's|^WEBSHIELD_ENABLED="no"|WEBSHIELD_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    echo "  WebShield ................ enabled"
    sed -i 's|^CLEANUP_ENABLED="no"|CLEANUP_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
    echo "  Auto Cleanup ............. enabled"
    done_ok "Protection modules configured"

    section "Configuring Firewall (UFW)"
    if command -v ufw &>/dev/null; then
        sed -i 's|^UFW_ENABLED="no"|UFW_ENABLED="yes"|' "$CONFIG_DIR/jabali-security.conf" 2>/dev/null
        ufw default deny incoming >/dev/null 2>&1 || true
        ufw default allow outgoing >/dev/null 2>&1 || true

        # Open standard hosting ports
        _open_port() { ufw allow "$1" comment "$2" >/dev/null 2>&1 || true; printf "  %-8s %-18s %s\n" "$1" "$2" "$3"; }

        echo ""
        printf "  %-8s %-18s %s\n" "PORT" "SERVICE" "NOTES"
        printf "  %-8s %-18s %s\n" "────" "──────────────────" "────────────────────────────"
        _open_port "22/tcp"   "SSH"                  ""
        _open_port "80/tcp"   "HTTP"                 "ACME, autoconfig, redirects"
        _open_port "443/tcp"  "HTTPS"                "Sites, webmail, phpMyAdmin"
        _open_port "25/tcp"   "SMTP"                 "Other mail servers connect here"
        _open_port "465/tcp"  "SMTPS"                "Mail clients"
        _open_port "587/tcp"  "Submission"            "Mail clients"
        _open_port "110/tcp"  "POP3"                 "Mail clients"
        _open_port "143/tcp"  "IMAP"                 "Mail clients"
        _open_port "993/tcp"  "IMAPS"                "Mail clients"
        _open_port "995/tcp"  "POP3S"                "Mail clients"
        if command -v named &>/dev/null || command -v bind9 &>/dev/null || [ -d "/etc/bind" ]; then
            _open_port "53/tcp" "DNS"                "BIND9 detected"
            _open_port "53/udp" "DNS"                "BIND9 detected"
        fi
        if [ -d "/var/www/jabali" ]; then
            _open_port "2223/tcp" "Jabali Panel"     "Admin + user panel"
        fi
        echo ""

        ufw --force enable 2>&1 | sed 's/^/  /'
        done_ok "Firewall configured"
    else
        echo "  UFW not available, skipping firewall setup."
    fi

    section "Hardening SSH (Jail Environment)"
    (
    # Run jail setup in subshell so failures don't kill the installer
    set +e

    # Create groups for SFTP and shell users
    groupadd sftpusers 2>/dev/null || true
    groupadd shellusers 2>/dev/null || true

    # Backup and configure sshd_config
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%Y%m%d%H%M%S)"
        echo "  sshd_config backed up"

        # Remove any existing Jabali SSH config block
        sed -i '/# Jabali SSH Jail Configuration/,/# End Jabali SSH Jail/d' /etc/ssh/sshd_config

        # Use internal-sftp (works inside chroot, no binary needed)
        sed -i 's|Subsystem\tsftp\t/usr/lib/openssh/sftp-server|Subsystem\tsftp\tinternal-sftp|' /etc/ssh/sshd_config

        # Append SSH jail configuration
        cat >> /etc/ssh/sshd_config << 'SSHJAIL'

# Jabali SSH Jail Configuration
# SFTP-only users (default for all panel users)
Match Group sftpusers
    ChrootDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTTY no
    X11Forwarding no

# Shell users (jailed with limited commands)
Match Group shellusers
    ChrootDirectory /var/jail
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
# End Jabali SSH Jail
SSHJAIL
        echo "  SSH jail rules added (sftpusers + shellusers)"
    fi

    # Set up jail directory structure
    mkdir -p /var/jail/{bin,lib,lib64,usr,etc,dev,home}
    mkdir -p /var/jail/usr/{bin,lib,share}
    mkdir -p /var/jail/usr/lib/x86_64-linux-gnu

    # Copy essential binaries to jail
    JAIL_BINS="bash sh ls cat cp mv rm mkdir rmdir pwd echo head tail grep sed awk wc sort uniq cut tr touch chmod find which"
    for bin in $JAIL_BINS; do
        if [ -f "/bin/$bin" ]; then
            cp "/bin/$bin" /var/jail/bin/ 2>/dev/null || true
        elif [ -f "/usr/bin/$bin" ]; then
            cp "/usr/bin/$bin" /var/jail/usr/bin/ 2>/dev/null || true
        fi
    done

    # Copy wp-cli if available
    [ -f "/usr/local/bin/wp" ] && cp /usr/local/bin/wp /var/jail/usr/bin/wp 2>/dev/null || true
    # Copy PHP for wp-cli
    [ -f "/usr/bin/php" ] && cp /usr/bin/php /var/jail/usr/bin/ 2>/dev/null || true
    # Copy env (needed by wp-cli shebang)
    [ -f "/usr/bin/env" ] && cp /usr/bin/env /var/jail/usr/bin/ 2>/dev/null || true

    # Copy required libraries for all jail binaries
    _copy_libs() {
        local binary="$1"
        [ -f "$binary" ] || return
        ldd "$binary" 2>/dev/null | grep -o '/[^ ]*' | while read -r lib; do
            if [ -f "$lib" ]; then
                local libdir
                libdir=$(dirname "$lib")
                mkdir -p "/var/jail$libdir"
                cp -n "$lib" "/var/jail$libdir/" 2>/dev/null || true
            fi
        done
    }
    for bin in /var/jail/bin/* /var/jail/usr/bin/*; do
        [ -f "$bin" ] && _copy_libs "$bin"
    done

    # Copy PHP extensions for wp-cli
    PHP_EXT_DIR=$(php -i 2>/dev/null | grep "^extension_dir" | awk '{print $3}')
    if [ -d "$PHP_EXT_DIR" ]; then
        mkdir -p "/var/jail$PHP_EXT_DIR"
        cp "$PHP_EXT_DIR"/*.so "/var/jail$PHP_EXT_DIR/" 2>/dev/null || true
        for ext in "$PHP_EXT_DIR"/*.so; do
            [ -f "$ext" ] && _copy_libs "$ext"
        done
    fi

    # Copy PHP CLI config (resolve symlinks)
    local php_ver
    php_ver=$(php -v 2>/dev/null | head -1 | grep -oP '\d+\.\d+' | head -1)
    if [ -n "$php_ver" ] && [ -d "/etc/php/$php_ver/cli" ]; then
        mkdir -p "/var/jail/etc/php/$php_ver/cli/conf.d"
        cp "/etc/php/$php_ver/cli/php.ini" "/var/jail/etc/php/$php_ver/cli/" 2>/dev/null || true
        sed -i 's/;date.timezone =/date.timezone = UTC/' "/var/jail/etc/php/$php_ver/cli/php.ini" 2>/dev/null || true
        for f in /etc/php/"$php_ver"/cli/conf.d/*.ini; do
            if [ -L "$f" ]; then
                cp "$(readlink -f "$f")" "/var/jail/etc/php/$php_ver/cli/conf.d/$(basename "$f")" 2>/dev/null || true
            elif [ -f "$f" ]; then
                cp "$f" "/var/jail/etc/php/$php_ver/cli/conf.d/" 2>/dev/null || true
            fi
        done
        echo "  PHP $php_ver CLI copied to jail"
    fi

    # Create essential device nodes
    mknod -m 666 /var/jail/dev/null c 1 3 2>/dev/null || true
    mknod -m 666 /var/jail/dev/zero c 1 5 2>/dev/null || true
    mknod -m 666 /var/jail/dev/random c 1 8 2>/dev/null || true
    mknod -m 666 /var/jail/dev/urandom c 1 9 2>/dev/null || true
    mknod -m 666 /var/jail/dev/tty c 5 0 2>/dev/null || true

    # Create minimal /etc files in jail
    grep -E "^(root|nobody)" /etc/passwd > /var/jail/etc/passwd 2>/dev/null || true
    grep -E "^(root|nogroup)" /etc/group > /var/jail/etc/group 2>/dev/null || true
    cp /etc/nsswitch.conf /var/jail/etc/ 2>/dev/null || true
    cp /etc/hosts /var/jail/etc/ 2>/dev/null || true

    # Copy timezone data
    mkdir -p /var/jail/usr/share/zoneinfo
    cp -r /usr/share/zoneinfo/* /var/jail/usr/share/zoneinfo/ 2>/dev/null || true
    ln -sf /usr/share/zoneinfo/UTC /var/jail/etc/localtime 2>/dev/null || true

    # Set permissions
    chown root:root /var/jail
    chmod 755 /var/jail

    # Restart SSH
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
    ) || true
    done_ok "SSH hardened (SFTP jail + shell jail with wp-cli)"

    section "System Tuning"
    current_watches=$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo 0)
    if [ "$current_watches" -lt 524288 ]; then
        echo "fs.inotify.max_user_watches=524288" > "$SYSCTL_CONF"
        sysctl -p "$SYSCTL_CONF" 2>/dev/null || true
        echo "  inotify watch limit raised to 524288"
    else
        echo "  inotify watch limit OK ($current_watches)"
    fi
    done_ok "System tuning applied"

    section "Installing Python Dependencies"
    _venv_dir="$INSTALL_DIR/venv"
    if [ ! -d "$_venv_dir" ] || [ ! -f "$_venv_dir/bin/python" ]; then
        if ! python3 -m venv "$_venv_dir" 2>/dev/null; then
            run_with_spinner "Installing python3-venv" pkg_install python3-venv
            python3 -m venv "$_venv_dir"
        fi
    fi

    if [ -f "$_venv_dir/bin/pip" ]; then
        local pip_pkgs="pydantic>=2.0 yara-x>=0.11 click>=8.0 aiohttp>=3.9 pyyaml>=6.0 aiosqlite>=0.20"
        if command -v uv &>/dev/null; then
            # shellcheck disable=SC2086
            run_with_spinner "Installing Python packages (uv)" \
                uv pip install --python "$_venv_dir/bin/python" $pip_pkgs
        else
            # shellcheck disable=SC2086
            run_with_spinner "Installing Python packages (pip)" \
                "$_venv_dir/bin/pip" install --quiet --no-cache-dir $pip_pkgs
        fi
    fi

    section "Starting Services"
    cp "$INSTALL_DIR/etc/jabali-security.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true
    echo "  jabali-security daemon .... started"

    done_ok "Services started"

    # ── Summary ───────────────────────────────────────────────────────
    echo ""
    bold "╔════════════════════════════════════════════════════════════╗"
    bold "║          Installation Complete                             ║"
    bold "╚════════════════════════════════════════════════════════════╝"
    echo ""
    green "  Jabali Security installed successfully!"
    echo ""
    echo "  Daemon:    systemctl status $SERVICE_NAME"
    echo "  Config:    $CONFIG_DIR/jabali-security.conf"
    echo "  CLI:       jabali-security --help"
    echo "  Logs:      journalctl -u $SERVICE_NAME -f"
    echo ""
}

# ── Update ────────────────────────────────────────────────────────────────

do_update() {
    require_root
    bold "Updating Jabali Security..."

    if [ ! -d "$INSTALL_DIR" ]; then
        red "Error: Jabali Security is not installed at $INSTALL_DIR"
        red "Run the installer without --update to install first."
        exit 1
    fi

    # Clone latest code
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    echo "Pulling latest code..."
    git clone --depth 1 --quiet "$REPO_URL" "$tmp_dir"

    # Stop services before updating files
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    # -- Update application files (preserve config/data/venv) --
    cp "$tmp_dir"/daemon/*.py "$INSTALL_DIR/daemon/"
    cp "$tmp_dir"/lib/*.py "$INSTALL_DIR/lib/"
    for subdir in watcher scanner bruteforce waf proactive cleanup threat_intel webshield ufw sshjail; do
        mkdir -p "$INSTALL_DIR/lib/$subdir"
        cp "$tmp_dir"/lib/$subdir/*.py "$INSTALL_DIR/lib/$subdir/" 2>/dev/null || true
    done
    mkdir -p "$INSTALL_DIR/api/routes"
    cp "$tmp_dir"/api/*.py "$INSTALL_DIR/api/"
    cp "$tmp_dir"/api/routes/*.py "$INSTALL_DIR/api/routes/"
    cp "$tmp_dir"/rules/*.yar "$INSTALL_DIR/rules/" 2>/dev/null || true
    cp "$tmp_dir"/etc/jabali-security.service "$INSTALL_DIR/etc/"
    cp -r "$tmp_dir"/etc/webshield "$INSTALL_DIR/etc/" 2>/dev/null || true
    cp "$tmp_dir"/bin/jabali-security "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/jabali-security"

    # -- Update Jabali Panel plugin if panel exists --
    JABALI_PANEL_DIR="/var/www/jabali"
    if [ -d "$JABALI_PANEL_DIR/app/Filament" ] && [ -d "$tmp_dir/panel" ]; then
        echo "Updating Jabali Panel security plugin..."
        mkdir -p "$JABALI_PANEL_DIR/app/JabaliSecurity/Pages"
        mkdir -p "$JABALI_PANEL_DIR/app/JabaliSecurity/Widgets"
        mkdir -p "$JABALI_PANEL_DIR/app/JabaliSecurity/views"
        cp "$tmp_dir"/panel/JabaliSecurityPlugin.php "$JABALI_PANEL_DIR/app/JabaliSecurity/"
        cp "$tmp_dir"/panel/JabaliSecurityClient.php "$JABALI_PANEL_DIR/app/JabaliSecurity/"
        cp "$tmp_dir"/panel/Pages/*.php "$JABALI_PANEL_DIR/app/JabaliSecurity/Pages/"
        cp "$tmp_dir"/panel/Widgets/*.php "$JABALI_PANEL_DIR/app/JabaliSecurity/Widgets/"
        cp "$tmp_dir"/panel/views/*.blade.php "$JABALI_PANEL_DIR/app/JabaliSecurity/views/"
        echo "Panel plugin updated."
    fi

    # Clean up
    rm -rf "$tmp_dir"

    # -- Update systemd service files --
    cp "$INSTALL_DIR/etc/jabali-security.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true

    # -- Restart services --
    systemctl start "$SERVICE_NAME" 2>/dev/null || true

    echo ""
    green "Jabali Security updated successfully!"
    echo "  Version: $(grep 'VERSION = ' "$INSTALL_DIR/lib/constants.py" 2>/dev/null | cut -d'"' -f2 || echo '?')"
}

# ── Main ───────────────────────────────────────────────────────────────────

case "${1:-}" in
    --uninstall)
        do_uninstall
        ;;
    --update)
        do_update
        ;;
    --help|-h)
        echo "Usage: $0 [--uninstall|--update]"
        echo ""
        echo "  (no args)     Install Jabali Security"
        echo "  --update      Update to latest version (preserves config/data)"
        echo "  --uninstall   Completely remove Jabali Security (config, data, logs)"
        ;;
    "")
        do_install
        ;;
    *)
        red "Unknown option: $1"
        echo "Usage: $0 [--uninstall|--update]"
        exit 1
        ;;
esac
