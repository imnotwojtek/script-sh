#!/bin/bash

# Strict mode configuration
set -euo pipefail
IFS=$'\n\t'

# Script version
readonly VERSION="1.0.0"

# Configuration
readonly MIN_PASSWORD_LENGTH=32
readonly BACKUP_RETENTION_DAYS=7
readonly DEFAULT_PORT=2368
readonly GHOST_VERSION="5.71.1"  # Explicitly define Ghost version
readonly NODE_VERSION="18-alpine"
readonly MYSQL_VERSION="8.0"      # Updated from 5.7
readonly CONFIG_DIR="/etc/ghost-docker"
readonly DATA_DIR="/var/lib/ghost-docker"
readonly LOG_DIR="/var/log/ghost-docker"
readonly BACKUP_DIR="/var/backups/ghost-docker"

# Colors for logging
declare -r GREEN="\e[32m"
declare -r RED="\e[31m"
declare -r YELLOW="\e[33m"
declare -r BLUE="\e[34m"
declare -r NC="\e[0m"

# Logging functions with timestamps and proper error handling
log() {
    local level=$1
    shift
    local color=""
    case "$level" in
        "INFO") color=$GREEN ;;
        "WARN") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "DEBUG") color=$BLUE ;;
    esac
    echo -e "${color}[${level}] $(date '+%Y-%m-%d %H:%M:%S') - $*${NC}" >&2
}

log_info() { log "INFO" "$@"; }
log_warning() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# Error handling
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5
    log_error "Error in script at line $line_no: '$last_command' exited with status $exit_code"
    log_error "Function trace: $func_trace"
    cleanup
    exit "$exit_code"
}

# Cleanup function
cleanup() {
    log_info "Performing cleanup..."
    # Remove temporary files and directories
    rm -rf /tmp/ghost-install-* 2>/dev/null || true
}

# Security hardening functions
harden_system() {
    log_info "Applying system hardening measures..."
    
    # Update system packages
    apt update && apt upgrade -y
    
    # Install security packages
    DEBIAN_FRONTEND=noninteractive apt install -y \
        fail2ban \
        ufw \
        apparmor \
        apparmor-utils \
        auditd \
        rkhunter
    
    # Configure firewall
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw --force enable
    
    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
EOF
    systemctl restart fail2ban
    
    # Configure AppArmor
    aa-enforce /etc/apparmor.d/*
    
    # Enable and configure auditd
    systemctl enable auditd
    systemctl start auditd
    
    # Configure system limits
    cat >> /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
EOF

    # Secure shared memory
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    
    # Disable unnecessary services
    systemctl disable bluetooth.service || true
    systemctl disable cups.service || true
    
    # Set secure permissions for sensitive files
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    
    log_info "System hardening completed"
}

# Enhanced password generation with stronger requirements
generate_password() {
    local length=${1:-$MIN_PASSWORD_LENGTH}
    local password
    
    # Generate password with specific character classes
    password=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()-_=+{}[]' < /dev/urandom | head -c "$length")
    
    # Ensure password meets complexity requirements
    while [[ ! "$password" =~ [A-Z] || 
            ! "$password" =~ [a-z] || 
            ! "$password" =~ [0-9] || 
            ! "$password" =~ [!@#$%^&*()-_=+{}[\]] ||
            ${#password} -lt $MIN_PASSWORD_LENGTH ]]; do
        password=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()-_=+{}[]' < /dev/urandom | head -c "$length")
    done
    
    echo "$password"
}

# Enhanced user creation with security checks
create_sudo_user() {
    local username="$1"
    local password
    
    if [[ -z "$username" ]]; then
        log_error "Username not provided"
        return 1
    }
    
    # Validate username format
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
        log_error "Invalid username format"
        return 1
    }
    
    if id "$username" &>/dev/null; then
        log_warning "User $username already exists"
        return 0
    }
    
    password=$(generate_password)
    
    log_info "Creating new user: $username"
    useradd -m -s /bin/bash -G sudo "$username"
    
    # Set password with security policies
    echo "$username:$password" | chpasswd
    passwd -e "$username"  # Force password change on first login
    
    # Configure sudo access with restrictions
    echo "$username ALL=(ALL:ALL) PASSWD: ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    
    # Set up SSH directory with secure permissions
    local user_home
    user_home=$(getent passwd "$username" | cut -d: -f6)
    
    mkdir -p "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    touch "$user_home/.ssh/authorized_keys"
    chmod 600 "$user_home/.ssh/authorized_keys"
    chown -R "$username:$username" "$user_home/.ssh"
    
    log_info "User $username created successfully"
    echo "Initial password: $password"
    echo "Please change this password immediately upon first login"
}

# Enhanced package installation with verification
install_packages() {
    log_info "Installing required packages..."
    
    # Add necessary repositories
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
    
    apt update
    
    # Install packages with version pinning
    DEBIAN_FRONTEND=noninteractive apt install -y \
        docker-ce=5:24.0.0-1~ubuntu.22.04~jammy \
        docker-ce-cli=5:24.0.0-1~ubuntu.22.04~jammy \
        containerd.io=1.6.21-1 \
        docker-compose-plugin=2.21.0-1~ubuntu.22.04~jammy \
        nginx=1.18.0-6ubuntu14.4 \
        certbot=1.21.0-1ubuntu1 \
        python3-certbot-nginx=1.21.0-1 \
        fail2ban=0.11.2-4

    # Verify package installations
    local packages=("docker-ce" "nginx" "certbot")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log_error "Failed to install $package"
            return 1
        fi
    done
    
    # Configure Docker daemon with security options
    cat > /etc/docker/daemon.json << EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "userns-remap": "default",
    "no-new-privileges": true,
    "seccomp-profile": "/etc/docker/seccomp-profile.json",
    "selinux-enabled": true,
    "live-restore": true
}
EOF

    # Restart Docker with new configuration
    systemctl restart docker
    
    log_info "Package installation completed"
}

# Enhanced directory setup with secure permissions
setup_directories() {
    log_info "Creating directory structure..."
    
    local -a dirs=(
        "$CONFIG_DIR"
        "$DATA_DIR"
        "$LOG_DIR"
        "$BACKUP_DIR"
        "$CONFIG_DIR/ssl"
        "$CONFIG_DIR/nginx"
        "$DATA_DIR/ghost"
        "$DATA_DIR/mysql"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chmod 750 "$dir"
    done
    
    # Set specific permissions for sensitive directories
    chmod 700 "$CONFIG_DIR/ssl"
    chmod 700 "$DATA_DIR/mysql"
    
    # Create log files with proper permissions
    touch "$LOG_DIR/ghost.log" "$LOG_DIR/nginx.log" "$LOG_DIR/mysql.log"
    chmod 640 "$LOG_DIR"/*.log
    
    log_info "Directory structure created"
}

# Generate secure configuration files
create_config_files() {
    log_info "Creating configuration files..."
    
    # Generate Docker Compose file with security enhancements
    cat > "$CONFIG_DIR/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  mysql:
    image: mysql:${MYSQL_VERSION}
    container_name: ghost_mysql
    environment:
      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mysql_root_password
      MYSQL_DATABASE: ghost_db
      MYSQL_USER: ghost_user
      MYSQL_PASSWORD_FILE: /run/secrets/mysql_password
    volumes:
      - mysql_data:/var/lib/mysql
      - ${CONFIG_DIR}/mysql/my.cnf:/etc/mysql/my.cnf:ro
    networks:
      - ghost_internal
    restart: unless-stopped
    secrets:
      - mysql_root_password
      - mysql_password
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 3
    security_opt:
      - no-new-privileges:true
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  ghost:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        GHOST_VERSION: ${GHOST_VERSION}
        NODE_VERSION: ${NODE_VERSION}
    container_name: ghost_app
    environment:
      NODE_ENV: production
      database__client: mysql
      database__connection__host: mysql
      database__connection__user: ghost_user
      database__connection__password_FILE: /run/secrets/mysql_password
      database__connection__database: ghost_db
    volumes:
      - ghost_content:/var/lib/ghost/content
      - ${CONFIG_DIR}/ghost:/var/lib/ghost/config:ro
    depends_on:
      mysql:
        condition: service_healthy
    networks:
      - ghost_internal
    restart: unless-stopped
    secrets:
      - mysql_password
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:2368/ghost/api/v3/admin/"]
      interval: 30s
      timeout: 10s
      retries: 3
    security_opt:
      - no-new-privileges:true
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:stable-alpine
    container_name: ghost_nginx
    volumes:
      - ${CONFIG_DIR}/nginx:/etc/nginx/conf.d:ro
      - ${CONFIG_DIR}/ssl:/etc/ssl:ro
      - ${LOG_DIR}:/var/log/nginx
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      ghost:
        condition: service_healthy
    networks:
      - ghost_internal
      - ghost_external
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nginx", "-t"]
      interval: 30s
      timeout: 10s
      retries: 3
    security_opt:
      - no-new-privileges:true
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  ghost_internal:
    driver: bridge
    internal: true
  ghost_external:
    driver: bridge

volumes:
  mysql_data:
  ghost_content:

secrets:
  mysql_root_password:
    file: ${CONFIG_DIR}/secrets/mysql_root_password.txt
  mysql_password:
    file: ${CONFIG_DIR}/secrets/mysql_password.txt
EOF

    # Generate secure MySQL configuration
    cat > "$CONFIG_DIR/mysql/my.cnf" << 'EOF'
[mysqld]
# Security settings
local-infile=0
secure-file-priv=/var/lib/mysql-files
skip-symbolic-links

# Performance settings
innodb_buffer_pool_size=1G
innodb_log_file_size=256M
innodb_flush_log_at_trx_commit=1
innodb_flush_method=O_DIRECT

# Connection settings
max_connections=100
wait_timeout=60
interactive_timeout=60

# Logging
slow_query_log=1
long_query_time=2
slow_query_log_file=/var/log/mysql/slow.log
log_error=/var/log/mysql/error.log

[client]
default-character-set=utf8mb4

[mysql]
default-character-set=utf8mb4
EOF

    # Generate Nginx configuration with security headers
    cat > "$CONFIG_DIR/nginx/ghost.conf" << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN_NAME};
    
    # Redirect all HTTP traffic to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN_NAME};

    # SSL configuration
    ssl_certificate /etc/ssl/live/${DOMAIN_NAME}/fullchain.pem;
    ssl_certificate_key /etc/ssl/live/${DOMAIN_NAME}/privkey.pem;
    ssl_trusted_certificate /etc/ssl/live/${DOMAIN_NAME}/chain.pem;

    # SSL optimization
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (uncomment if domain is preloaded)
    # add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline' 'unsafe-eval'" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # Proxy settings
    location / {
        proxy_pass http://ghost:2368;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        proxy_max_temp_file_size 0;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static content handling
    location ~* \.(jpg|jpeg|gif|png|css|js|ico|xml|woff|woff2|ttf|svg)$ {
        access_log off;
        expires 30d;
        add_header Pragma public;
        add_header Cache-Control "public, no-transform";
        proxy_pass http://ghost:2368;
    }

    # Deny access to sensitive locations
    location ~ /\.(?!well-known) {
        deny all;
    }
}
EOF

    # Generate Docker build configuration
    cat > "$CONFIG_DIR/Dockerfile" << 'EOF'
ARG NODE_VERSION
FROM node:${NODE_VERSION} as builder

ARG GHOST_VERSION
ENV GHOST_VERSION=${GHOST_VERSION}

# Install dependencies and Ghost CLI
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    gcc \
    libc6-compat \
    vips-dev \
    sqlite-dev \
    && npm install --location=global ghost-cli@latest

# Create Ghost working directory
WORKDIR /var/lib/ghost

# Install Ghost with specific version
RUN ghost install ${GHOST_VERSION} local \
    --no-prompt \
    --no-stack \
    --no-setup-linux-user \
    --no-setup-nginx \
    --no-setup-mysql \
    --no-setup-ssl \
    --no-start

# Production image
FROM node:${NODE_VERSION}

# Install runtime dependencies
RUN apk add --no-cache \
    tini \
    vips-dev \
    sqlite-dev \
    && rm -rf /var/cache/apk/*

# Copy Ghost installation
COPY --from=builder /var/lib/ghost /var/lib/ghost

WORKDIR /var/lib/ghost

# Set up volumes
VOLUME /var/lib/ghost/content

# Set up user
RUN addgroup -S ghost && adduser -S -G ghost ghost \
    && chown -R ghost:ghost /var/lib/ghost

USER ghost

# Use tini as init
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "current/index.js"]
EOF

    # Generate backup script
    cat > "$CONFIG_DIR/scripts/backup.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/ghost-docker}"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-7}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup MySQL database
docker exec ghost_mysql mysqldump \
    --single-transaction \
    --quick \
    --lock-tables=false \
    -u root \
    -p"$(cat ${CONFIG_DIR}/secrets/mysql_root_password.txt)" \
    ghost_db > "$BACKUP_DIR/ghost_db_$TIMESTAMP.sql"

# Backup Ghost content
tar -czf "$BACKUP_DIR/ghost_content_$TIMESTAMP.tar.gz" \
    -C /var/lib/ghost/content .

# Backup configuration
tar -czf "$BACKUP_DIR/ghost_config_$TIMESTAMP.tar.gz" \
    -C "$CONFIG_DIR" .

# Remove old backups
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete

# Verify backups
if [[ ! -s "$BACKUP_DIR/ghost_db_$TIMESTAMP.sql" ]]; then
    echo "Database backup failed!"
    exit 1
fi

if [[ ! -s "$BACKUP_DIR/ghost_content_$TIMESTAMP.tar.gz" ]]; then
    echo "Content backup failed!"
    exit 1
fi

echo "Backup completed successfully at $(date)"
EOF
    chmod +x "$CONFIG_DIR/scripts/backup.sh"

    # Generate monitoring script
    cat > "$CONFIG_DIR/scripts/monitor.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

# Check container status
check_container() {
    local container_name=$1
    if ! docker ps -q -f name="$container_name" >/dev/null; then
        echo "WARNING: Container $container_name is not running!"
        return 1
    fi
    return 0
}

# Check system resources
check_resources() {
    # Check disk space
    local disk_usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    if (( disk_usage > 80 )); then
        echo "WARNING: Disk usage is high: ${disk_usage}%"
    fi

    # Check memory usage
    local memory_usage
    memory_usage=$(free | awk '/Mem:/ {printf("%.0f", $3/$2 * 100)}')
    if (( memory_usage > 80 )); then
        echo "WARNING: Memory usage is high: ${memory_usage}%"
    fi

    # Check load average
    local load_average
    load_average=$(uptime | awk -F'load average:' '{print $2}' | cut -d, -f1)
    if (( $(echo "$load_average > 2" | bc -l) )); then
        echo "WARNING: System load is high: $load_average"
    fi
}

# Main monitoring loop
main() {
    # Check containers
    local containers=("ghost_mysql" "ghost_app" "ghost_nginx")
    for container in "${containers[@]}"; do
        check_container "$container"
    done

    # Check resources
    check_resources

    # Check SSL certificate expiration
    if [[ -f "/etc/ssl/live/${DOMAIN_NAME}/fullchain.pem" ]]; then
        local days_until_expiry
        days_until_expiry=$(openssl x509 -enddate -noout -in "/etc/ssl/live/${DOMAIN_NAME}/fullchain.pem" | \
            awk -F'=' '{print $2}' | \
            xargs -I{} date -d "{}" +%s | \
            xargs -I{} echo "({} - $(date +%s))/(60*60*24)" | bc)
        
        if (( days_until_expiry < 30 )); then
            echo "WARNING: SSL certificate will expire in $days_until_expiry days"
        fi
    fi
}

main "$@"
EOF
    chmod +x "$CONFIG_DIR/scripts/monitor.sh"

    log_info "Configuration files created successfully"
}

# Main deployment function
deploy_ghost() {
    log_info "Starting Ghost deployment..."

    # Generate secrets
    mkdir -p "$CONFIG_DIR/secrets"
    generate_password > "$CONFIG_DIR/secrets/mysql_root_password.txt"
    generate_password > "$CONFIG_DIR/secrets/mysql_password.txt"
    chmod 600 "$CONFIG_DIR/secrets/"*

    # Start services
    cd "$CONFIG_DIR"
    docker-compose up -d

    # Wait for services to be ready
    local timeout=300
    local interval=5
    local elapsed=0

    while (( elapsed < timeout )); do
        if curl -s "http://localhost:2368/ghost/api/v3/admin/" >/dev/null; then
            log_info "Ghost is running and accessible"
            break
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    if (( elapsed >= timeout )); then
        log_error "Timeout waiting for Ghost to start"
        return 1
    fi

    # Set up scheduled tasks
    (crontab -l 2>/dev/null || true; echo "0 3 * * * $CONFIG_DIR/scripts/backup.sh") | crontab -
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $CONFIG_DIR/scripts/monitor.sh") | crontab -

    log_info "Ghost deployment completed successfully"
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                DOMAIN_NAME="$2"
                shift 2
                ;;
            --email)
                ADMIN_EMAIL="$2"
                shift 2
                ;;
            --version)
                echo "Ghost Docker Installer v${VERSION}"
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown parameter: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate required parameters
    if [[ -z "${DOMAIN_NAME:-}" ]] || [[ -z "${ADMIN_EMAIL:-}" ]]; then
        log_error "Missing required parameters"
        show_help
        exit 1
    }

    # Check system requirements
    check_requirements

    # Execute main deployment steps
    require_root
    harden_system
    create_sudo_user "ghostadmin"
    install_packages
    setup_directories
    create_config_files
    deploy_ghost

    log_info "Installation completed successfully"
    echo "Ghost is now running at https://${DOMAIN_NAME}"
    echo "Admin interface: https://${DOMAIN_NAME}/ghost/"
    echo "Please check $LOG_DIR for logs"
}

# Execute main function
main "$@"
EOF
