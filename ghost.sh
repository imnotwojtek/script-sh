#!/bin/bash

set -euo pipefail

# Funkcja logowania zdarzeń
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Funkcja generowania losowego hasła
generate_password() {
  tr -dc 'A-Za-z0-9!@#$%^&*()-_=+{}[]' < /dev/urandom | head -c 24
}

# Wstępna konfiguracja
log "Rozpoczynam konfigurację środowiska Docker dla Ghost..."

# 1. Instalacja Docker i Docker Compose
log "Instalacja Docker i Docker Compose..."
sudo apt update
sudo apt install -y docker.io docker-compose

# 2. Tworzenie struktury katalogów
log "Tworzenie struktury katalogów..."
mkdir -p /ghost-docker
cd /ghost-docker

# 3. Utworzenie pliku Dockerfile
log "Tworzenie Dockerfile..."

cat << 'EOF' > Dockerfile
# Wybieramy obraz z Node.js (Alpine dla mniejszego rozmiaru)
FROM node:18-alpine AS build

# Instalacja zależności
RUN apk update && apk add --no-cache \
    curl \
    unzip \
    pwgen \
    jq \
    mysql-client \
    nginx \
    && rm -rf /var/cache/apk/*

# Instalacja Ghost-CLI
RUN npm install -g ghost-cli

# Ustawienia katalogów
WORKDIR /var/www/ghost

# Instalacja Ghost
RUN ghost install --no-prompt --process systemd --no-setup-ssl --no-setup-nginx

# Kopiowanie plików do obrazu
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Uruchamianie kontenera
CMD ["/start.sh"]
EOF

# 4. Utworzenie pliku startowego `start.sh`
log "Tworzenie skryptu startowego..."

cat << 'EOF' > start.sh
#!/bin/bash

# Uruchamiamy Nginx
service nginx start

# Uruchamiamy Ghost
ghost start

# Logowanie procesu
echo "Ghost uruchomiony na porcie 2368"
EOF

chmod +x start.sh

# 5. Utworzenie pliku konfiguracyjnego Nginx
log "Tworzenie konfiguracji Nginx..."

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

        # Ochrona przed atakami DDoS i zwiększenie bezpieczeństwa
        proxy_set_header X-Frame-Options SAMEORIGIN;
        proxy_set_header X-Content-Type-Options nosniff;
        proxy_set_header Referrer-Policy strict-origin-when-cross-origin;
        proxy_set_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';";

        # Optymalizacja cache dla zasobów statycznych
        location ~* \.(jpg|jpeg|png|gif|css|js|woff|woff2|ttf|svg|ico)$ {
            expires 1y;
            add_header Cache-Control "public, immutable, no-transform, max-age=31536000";
        }
    }

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # HSTS: Wymusza HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # SSL Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
}
EOF

# 6. Utworzenie pliku `docker-compose.yml`
log "Tworzenie pliku docker-compose.yml..."

cat << 'EOF' > docker-compose.yml
version: '3.8'

services:
  mysql:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:-$(generate_password)}
      MYSQL_DATABASE: 'ghost_db'
      MYSQL_USER: 'ghost_user'
      MYSQL_PASSWORD: ${MYSQL_PASSWORD:-$(generate_password)}
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
      database__connection__password: ${MYSQL_PASSWORD:-$(generate_password)}
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

# 7. Utworzenie katalogu na certyfikaty SSL
log "Tworzenie katalogu SSL..."

mkdir -p ssl_config

# 8. Utworzenie skryptu do generowania SSL
log "Tworzenie skryptu certbot.sh..."

cat << 'EOF' > ssl_config/certbot.sh
#!/bin/bash

# Wykonaj Certbot do utworzenia certyfikatu
certbot --nginx -d example.com --non-interactive --agree-tos --email admin@example.com

# Dodaj cron do odnowienia certyfikatu
echo "0 0 * * * root certbot renew --quiet" >> /etc/crontab
EOF

chmod +x ssl_config/certbot.sh

# 9. Budowa obrazu Docker
log "Budowa obrazu Docker..."
docker-compose build

# 10. Uruchomienie aplikacji w Dockerze
log "Uruchamianie aplikacji w Dockerze..."
docker-compose up -d

# Finalizacja
log "Instalacja zakończona. Ghost działa w kontenerze Docker. Przejdź do 'http://localhost' lub 'https://example.com' w przeglądarce."
