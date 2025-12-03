#!/bin/bash

set -e

echo "=========================================="
echo "OpenSSH Server Installer for dstack"
echo "=========================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Persistent storage paths
SSH_DATA_DIR="/dstack/persistent/ssh"

# Configuration with defaults
: "${SSH_PORT:=22}"
: "${SSH_PERMIT_ROOT_LOGIN:=prohibit-password}"

log_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

host_run() {
    nsenter -t 1 -m -p -n "$@"
}

ensure_path_writable() {
    local path="$1"
    log_info "Checking if ${path} is writable on host..."

    if host_run touch "${path}/.write_test" 2>/dev/null; then
        host_run rm -f "${path}/.write_test"
        log_info "${path} is writable"
        return 0
    fi

    log_warning "${path} is read-only, mounting overlay..."

    # Copy and run the overlay mount script on host
    cp /usr/local/bin/mount-overlay.sh /host/tmp/
    chmod +x /host/tmp/mount-overlay.sh
    if host_run /tmp/mount-overlay.sh "${path}"; then
        log_success "${path} overlay mounted"
        return 0
    else
        log_error "Failed to mount ${path} overlay"
        return 1
    fi
}

show_config() {
    log_info "Configuration:"
    echo "  SSH_PORT=${SSH_PORT}"
    echo "  SSH_PERMIT_ROOT_LOGIN=${SSH_PERMIT_ROOT_LOGIN}"
    echo "  SSH_PUBKEY=${SSH_PUBKEY:+<set>}${SSH_PUBKEY:-<not set>}"
    echo "  SSH_GITHUB_USER=${SSH_GITHUB_USER:-<not set>}"
    echo
}

check_existing() {
    log_info "Checking existing installation..."

    if host_run systemctl list-unit-files | grep -q "sshd.service" ||
        [ -f /host/run/systemd/system/sshd.service ] ||
        [ -f /host/etc/systemd/system/sshd.service ]; then

        if host_run systemctl is-active sshd.service >/dev/null 2>&1; then
            log_warning "OpenSSH server already installed and running"
            echo "Service status:"
            host_run systemctl status sshd.service --no-pager 2>/dev/null | head -5 || true
            log_info "To reinstall, first remove existing service:"
            echo "  systemctl stop sshd"
            echo "  rm /run/systemd/system/sshd.service"
            echo "  systemctl daemon-reload"
            exit 0
        fi
    fi
}

copy_binaries() {
    log_info "Copying OpenSSH binaries to host..."

    cp /usr/sbin/sshd /host/usr/bin/
    cp /usr/bin/ssh /host/usr/bin/
    cp /usr/bin/ssh-keygen /host/usr/bin/
    cp /usr/bin/scp /host/usr/bin/
    cp /usr/bin/sftp /host/usr/bin/
    cp /usr/lib/openssh/sftp-server /host/usr/bin/

    mkdir -p /host/usr/libexec
    cp /usr/libexec/sshd-session /host/usr/libexec/

    chmod +x /host/usr/bin/sshd /host/usr/bin/ssh /host/usr/bin/ssh-keygen \
        /host/usr/bin/scp /host/usr/bin/sftp /host/usr/bin/sftp-server \
        /host/usr/libexec/sshd-session

    log_success "Binaries copied"
}

setup_sshd_user() {
    log_info "Setting up sshd privilege separation user..."

    # Check if sshd user exists on host
    if host_run id sshd >/dev/null 2>&1; then
        log_info "sshd user already exists on host"
        host_run id sshd
    else
        log_info "Creating sshd user on host..."

        local sshd_uid=74
        local sshd_gid=74

        if ! host_run grep -q "^sshd:" /etc/group 2>/dev/null; then
            host_run sh -c "echo 'sshd:x:${sshd_gid}:' >> /etc/group"
        fi

        if ! host_run grep -q "^sshd:" /etc/passwd 2>/dev/null; then
            host_run sh -c "echo 'sshd:x:${sshd_uid}:${sshd_gid}:Privilege-separated SSH:/run/sshd:/sbin/nologin' >> /etc/passwd"
        fi

        if host_run test -f /etc/shadow; then
            if ! host_run grep -q "^sshd:" /etc/shadow 2>/dev/null; then
                host_run sh -c "echo 'sshd:!:0::::::' >> /etc/shadow"
            fi
        fi

        # Verify user was created
        if host_run id sshd >/dev/null 2>&1; then
            log_success "sshd user created (uid=${sshd_uid})"
        else
            log_error "Failed to create sshd user"
            return 1
        fi
    fi

    # Create privilege separation directory
    host_run mkdir -p /run/sshd
    host_run chmod 0755 /run/sshd
}

setup_ssh_keys() {
    log_info "Setting up SSH host keys..."

    mkdir -p "/host${SSH_DATA_DIR}"

    if [[ ! -f "/host${SSH_DATA_DIR}/ssh_host_rsa_key" ]]; then
        log_info "Generating RSA host key..."
        ssh-keygen -t rsa -b 4096 -f "/host${SSH_DATA_DIR}/ssh_host_rsa_key" -N ""
    fi

    if [[ ! -f "/host${SSH_DATA_DIR}/ssh_host_ecdsa_key" ]]; then
        log_info "Generating ECDSA host key..."
        ssh-keygen -t ecdsa -b 521 -f "/host${SSH_DATA_DIR}/ssh_host_ecdsa_key" -N ""
    fi

    if [[ ! -f "/host${SSH_DATA_DIR}/ssh_host_ed25519_key" ]]; then
        log_info "Generating ED25519 host key..."
        ssh-keygen -t ed25519 -f "/host${SSH_DATA_DIR}/ssh_host_ed25519_key" -N ""
    fi

    log_success "Host keys ready in ${SSH_DATA_DIR}"
}

setup_authorized_keys() {
    log_info "Setting up authorized keys for root..."

    local keys_added=0
    local auth_keys_dir="/host${SSH_DATA_DIR}/keys/root"
    local auth_keys_file="${auth_keys_dir}/authorized_keys"

    mkdir -p "${auth_keys_dir}"

    # Add key from SSH_PUBKEY environment variable
    if [[ -n "${SSH_PUBKEY}" ]]; then
        log_info "Adding public key from SSH_PUBKEY..."
        echo "${SSH_PUBKEY}" > "${auth_keys_file}"
        chmod 600 "${auth_keys_file}"
        keys_added=1
        log_success "Public key added from SSH_PUBKEY"
    fi

    # Fetch keys from GitHub user
    if [[ -n "${SSH_GITHUB_USER}" ]]; then
        local github_url="https://github.com/${SSH_GITHUB_USER}.keys"
        log_info "Fetching public keys from GitHub user: ${SSH_GITHUB_USER}..."
        local fetched_keys
        if fetched_keys=$(wget -qO- "${github_url}" 2>/dev/null); then
            if [[ -n "${fetched_keys}" ]]; then
                if [[ ${keys_added} -eq 1 ]]; then
                    echo "${fetched_keys}" >> "${auth_keys_file}"
                else
                    echo "${fetched_keys}" > "${auth_keys_file}"
                    chmod 600 "${auth_keys_file}"
                fi
                keys_added=1
                log_success "Public keys imported from GitHub (${SSH_GITHUB_USER})"
            else
                log_warning "No keys found for GitHub user: ${SSH_GITHUB_USER}"
            fi
        else
            log_error "Failed to fetch keys from GitHub for user: ${SSH_GITHUB_USER}"
        fi
    fi

    if [[ ${keys_added} -eq 0 ]]; then
        log_warning "No SSH keys configured"
        log_warning "Set SSH_PUBKEY or SSH_GITHUB_USER, or manually add keys to ${SSH_DATA_DIR}/keys/root/authorized_keys"
    fi
}

setup_ssh_config() {
    log_info "Setting up SSH configuration..."

    log_info "Creating sshd_config (Port=${SSH_PORT}, PermitRootLogin=${SSH_PERMIT_ROOT_LOGIN})..."
    cat > /host${SSH_DATA_DIR}/sshd_config << EOF
# OpenSSH Server Configuration for dstack

Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Host keys (persistent storage)
HostKey ${SSH_DATA_DIR}/ssh_host_rsa_key
HostKey ${SSH_DATA_DIR}/ssh_host_ecdsa_key
HostKey ${SSH_DATA_DIR}/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication
PermitRootLogin ${SSH_PERMIT_ROOT_LOGIN}
PubkeyAuthentication yes
AuthorizedKeysFile ${SSH_DATA_DIR}/keys/%u/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

# Security
X11Forwarding no
PrintMotd yes

# SFTP
Subsystem sftp /usr/bin/sftp-server

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# Keep alive
ClientAliveInterval 60
ClientAliveCountMax 3
EOF

    host_run mkdir -p /run/sshd
    host_run chmod 0755 /run/sshd

    log_success "SSH configuration completed"
}

create_systemd_service() {
    log_info "Creating systemd service..."

    host_run mkdir -p /run/systemd/system

    cat > /host/run/systemd/system/sshd.service << EOF
[Unit]
Description=OpenSSH Server
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target

[Service]
Type=simple
ExecStartPre=/usr/bin/sshd -t -f ${SSH_DATA_DIR}/sshd_config
ExecStart=/usr/bin/sshd -D -f ${SSH_DATA_DIR}/sshd_config
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
KillMode=process
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    if [[ ! -f /host/run/systemd/system/sshd.service ]]; then
        log_error "Failed to create sshd.service"
        return 1
    fi

    host_run systemctl daemon-reload

    log_success "Systemd service created (transient until reboot)"
}

start_sshd() {
    log_info "Starting OpenSSH server..."

    if host_run systemctl start sshd.service; then
        sleep 1
        if host_run systemctl is-active sshd.service >/dev/null; then
            log_success "OpenSSH server started successfully"
        else
            log_error "Service started but not active"
            host_run systemctl status sshd.service --no-pager || true
            host_run journalctl -u sshd.service --no-pager -n 20 || true
        fi
    else
        log_error "Failed to start sshd.service"
        host_run systemctl status sshd.service --no-pager || true
        host_run journalctl -u sshd.service --no-pager -n 20 || true
    fi
}

show_status() {
    echo
    echo "=========================================="
    echo -e "${GREEN}OpenSSH Server Installation Complete!${NC}"
    echo "=========================================="
    echo
    echo "Status:"
    echo "  SSH Server: $(host_run systemctl is-active sshd.service)"
    echo "  Port: ${SSH_PORT}"
    echo
    echo "Configuration:"
    echo "  Config file: ${SSH_DATA_DIR}/sshd_config"
    echo "  Host keys:   ${SSH_DATA_DIR}/ssh_host_*_key"
    echo
    echo "Usage:"
    if [[ "${SSH_PORT}" == "22" ]]; then
        echo "  ssh root@<host-ip>"
    else
        echo "  ssh -p ${SSH_PORT} root@<host-ip>"
    fi
    echo
    echo "Management:"
    echo "  systemctl status sshd      # Check status"
    echo "  systemctl restart sshd     # Restart service"
    echo "  journalctl -u sshd         # View logs"
    echo
}

main() {
    show_config
    check_existing
    ensure_path_writable /usr
    ensure_path_writable /etc
    copy_binaries
    setup_sshd_user
    setup_ssh_keys
    setup_authorized_keys
    setup_ssh_config
    create_systemd_service
    start_sshd
    show_status
}

main "$@"
