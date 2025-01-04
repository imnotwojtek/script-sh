#!/bin/bash

set -euo pipefail

# Kolory dla lepszego logowania
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
NC="\e[0m" # No Color

# Funkcja logowania zdarzeń
log_info() {
  echo -e "${GREEN}[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_warning() {
  echo -e "${YELLOW}[WARNING] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_error() {
  echo -e "${RED}[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}" >&2
}

# Funkcja generowania losowego hasła z minimalnymi wymaganiami
generate_password() {
  local password
  password=$(tr -dc 'A-Za-z0-9!@#$%^&*()-_=+{}[]' < /dev/urandom | head -c 24)
  if [[ ! "$password" =~ [A-Z] || ! "$password" =~ [a-z] || ! "$password" =~ [0-9] || ! "$password" =~ [!@#$%^&*()-_=+{}[]] ]]; then
    log_warning "Wygenerowane hasło nie spełnia minimalnych wymagań. Generowanie ponowne..."
    generate_password
  else
    echo "$password"
  fi
}

# Funkcja sprawdzania uprawnień
require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    log_error "Ten skrypt wymaga uprawnień administratora. Uruchom ponownie jako root lub użyj sudo."
    exit 1
  fi
}

# Funkcja tworzenia użytkownika z uprawnieniami sudo
create_sudo_user() {
  local username="$1"
  if id "$username" &>/dev/null; then
    log_warning "Użytkownik $username już istnieje."
  else
    log_info "Tworzenie nowego użytkownika: $username"
    password=$(generate_password)
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    usermod -aG sudo "$username"
    log_info "Utworzono użytkownika $username z hasłem: $password"
  fi
}

# Funkcja instalacji wymaganych pakietów
install_packages() {
  log_info "Sprawdzanie i instalacja wymaganych pakietów..."
  apt update
  DEBIAN_FRONTEND=noninteractive apt install -y docker.io docker-compose curl unzip pwgen jq mysql-client nginx certbot
  log_info "Pakiety zostały zainstalowane."
}

# Funkcja konfiguracji katalogów
setup_directories() {
  log_info "Tworzenie struktury katalogów..."
  mkdir -p /ghost-docker
  cd /ghost-docker
}

# Funkcja tworzenia plików konfiguracyjnych
create_files() {
  log_info "Tworzenie plików konfiguracyjnych..."

  cat << 'EOF' > Dockerfile
FROM node:18-alpine AS build
RUN apk update && apk add --no-cache curl unzip pwgen jq mysql-client nginx \
    && rm -rf /var/cache/apk/*
RUN npm install -g ghost-cli
WORKDIR /var/www/ghost
RUN ghost install --no-prompt --process systemd --no-setup-ssl --no-setup-nginx
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
EOF

  cat << 'EOF' > start.sh
#!/bin/bash
service nginx start
ghost start
echo "Ghost uruchomiony na porcie 2368"
EOF

  chmod +x start.sh

  cat << 'EOF' > ghost_nginx_config
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://ghost:2368;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header X-Frame-Options SAMEORIGIN;
        proxy_set_header X-Content-Type-Options nosniff;
        proxy_set_header Referrer-Policy strict-origin-when-cross-origin;
        proxy_set_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';";

        location ~* \.(jpg|jpeg|png|gif|css|js|woff|woff2|ttf|svg|ico)$ {
            expires 1y;
            add_header Cache-Control "public, immutable, no-transform, max-age=31536000";
        }
    }

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
}
EOF

  cat << 'EOF' > docker-compose.yml
version: '3.8'
services:
  mysql:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: "${MYSQL_ROOT_PASSWORD:-$(generate_password)}"
      MYSQL_DATABASE: 'ghost_db'
      MYSQL_USER: 'ghost_user'
      MYSQL_PASSWORD: "${MYSQL_PASSWORD:-$(generate_password)}"
    volumes:
      - mysql_data:/var/lib/mysql
    networks:
      - ghost_network
    restart: always

  ghost:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      database__client: mysql
      database__connection__host: mysql
      database__connection__user: ghost_user
      database__connection__password: "${MYSQL_PASSWORD:-$(generate_password)}"
      database__connection__database: ghost_db
    volumes:
      - ghost_data:/var/www/ghost
    depends_on:
      - mysql
    networks:
      - ghost_network
    ports:
      - "2368:2368"
    restart: always

  nginx:
    image: nginx:latest
    volumes:
      - ./ghost_nginx_config:/etc/nginx/conf.d
      - ghost_data:/var/www/ghost
    depends_on:
      - ghost
    ports:
      - "80:80"
      - "443:443"
    networks:
      - ghost_network
    restart: always

  certbot:
    image: certbot/certbot
    volumes:
      - ./ssl_config:/etc/letsencrypt
      - ./ghost_nginx_config:/etc/nginx/conf.d
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
    networks:
      - ghost_network
    restart: always

  watchtower:
    image: containrrr/watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - ghost_network
    restart: always

networks:
  ghost_network:
    driver: bridge

volumes:
  mysql_data:
  ghost_data:
EOF

  mkdir -p ssl_config
  cat << 'EOF' > ssl_config/certbot.sh
#!/bin/bash
certbot --nginx -d example.com --non-interactive --agree-tos --email admin@example.com
echo "0 0 * * * root certbot renew --quiet" >> /etc/crontab
EOF

  chmod +x ssl_config/certbot.sh
}

# Funkcja budowy obrazu Docker i uruchomienia kontenerów
build_and_run() {
  log_info "Budowa obrazu Docker..."
  docker-compose build

  log_info "Uruchamianie aplikacji w Dockerze..."
  docker-compose up -d
}

# Główna logika skryptu
main() {
  require_root
  create_sudo_user "ghostadmin"
  install_packages
  setup_directories
  create_files
  build_and_run
  log_info "Instalacja zakończona. Ghost działa w kontenerze Docker. Przejdź do 'http://localhost' lub 'https://example.com' w przeglądarce."
}

main
