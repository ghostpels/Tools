#!/bin/bash

#############################################
# WordPress Pentesting Lab Auto Setup
# Author: Ghostpels - hehehehe
# Description: Automated WordPress lab installation with Docker
#############################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/wordpress-lab"
DB_ROOT_PASSWORD="rootpassword123"
DB_NAME="wordpress_lab"
DB_USER="wpuser"
DB_PASSWORD="wppassword123"

# Functions
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Script ini harus dijalankan sebagai root!"
        echo "Gunakan: sudo bash $0"
        exit 1
    fi
    print_success "Running as root"
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Tidak dapat mendeteksi OS"
        exit 1
    fi
    print_success "OS detected: $OS $VER"
}

check_docker() {
    if command -v docker &> /dev/null; then
        print_info "Docker sudah terinstall: $(docker --version)"
        return 0
    else
        return 1
    fi
}

check_docker_compose() {
    if command -v docker-compose &> /dev/null; then
        print_info "Docker Compose sudah terinstall: $(docker-compose --version)"
        return 0
    else
        return 1
    fi
}

install_docker() {
    print_info "Menginstall Docker..."
    
    # Update packages
    apt-get update -qq
    
    # Install dependencies
    apt-get install -y -qq apt-transport-https ca-certificates curl software-properties-common gnupg lsb-release
    
    # Add Docker's official GPG key
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Set up repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Start Docker
    systemctl start docker
    systemctl enable docker
    
    print_success "Docker berhasil diinstall"
}

install_docker_compose() {
    print_info "Menginstall Docker Compose..."
    
    # Download latest version
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    
    chmod +x /usr/local/bin/docker-compose
    
    # Create symlink for compatibility
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    print_success "Docker Compose berhasil diinstall"
}

create_project_directory() {
    print_info "Membuat direktori project..."
    
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Direktori $INSTALL_DIR sudah ada!"
        read -p "Hapus dan buat ulang? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cd $INSTALL_DIR
            if [ -f "docker-compose.yml" ]; then
                docker-compose down -v 2>/dev/null || true
            fi
            cd /
            rm -rf $INSTALL_DIR
            print_success "Direktori lama dihapus"
        else
            print_error "Instalasi dibatalkan"
            exit 1
        fi
    fi
    
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR
    print_success "Direktori project dibuat: $INSTALL_DIR"
}

create_docker_compose() {
    print_info "Membuat docker-compose.yml..."
    
    cat > docker-compose.yml <<'EOF'
version: '3.8'

services:
  db:
    image: mysql:8.0
    container_name: wp-mysql
    restart: always
    command: '--default-authentication-plugin=mysql_native_password'
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword123
      MYSQL_DATABASE: wordpress_lab
      MYSQL_USER: wpuser
      MYSQL_PASSWORD: wppassword123
    volumes:
      - db_data:/var/lib/mysql
    networks:
      - wp-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "root", "-prootpassword123"]
      interval: 10s
      timeout: 5s
      retries: 5

  wordpress:
    depends_on:
      db:
        condition: service_healthy
    image: wordpress:latest
    container_name: wp-app
    restart: always
    ports:
      - "80:80"
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wpuser
      WORDPRESS_DB_PASSWORD: wppassword123
      WORDPRESS_DB_NAME: wordpress_lab
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_MEMORY_LIMIT', '256M');
        define('WP_MAX_MEMORY_LIMIT', '512M');
    volumes:
      - wp_data:/var/www/html
      - ./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini
    networks:
      - wp-network

  phpmyadmin:
    image: phpmyadmin:latest
    container_name: wp-phpmyadmin
    restart: always
    ports:
      - "8080:80"
    environment:
      PMA_HOST: db
      PMA_PORT: 3306
      MYSQL_ROOT_PASSWORD: rootpassword123
    depends_on:
      - db
    networks:
      - wp-network

volumes:
  db_data:
  wp_data:

networks:
  wp-network:
    driver: bridge
EOF
    
    print_success "docker-compose.yml dibuat"
}

create_php_config() {
    print_info "Membuat konfigurasi PHP..."
    
    cat > uploads.ini <<'EOF'
file_uploads = On
memory_limit = 512M
upload_max_filesize = 500M
post_max_size = 500M
max_execution_time = 600
max_input_time = 600
EOF
    
    print_success "uploads.ini dibuat"
}

configure_firewall() {
    print_info "Mengkonfigurasi firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp comment 'WordPress' 2>/dev/null || true
        ufw allow 8080/tcp comment 'phpMyAdmin' 2>/dev/null || true
        print_success "UFW rules ditambahkan"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=8080/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        print_success "Firewalld rules ditambahkan"
    else
        print_warning "Firewall tidak terdeteksi, skip konfigurasi"
    fi
}

start_containers() {
    print_info "Menjalankan Docker containers..."
    
    docker-compose up -d
    
    print_info "Menunggu MySQL siap..."
    sleep 10
    
    # Wait for MySQL to be ready
    MAX_TRIES=30
    COUNT=0
    while [ $COUNT -lt $MAX_TRIES ]; do
        if docker exec wp-mysql mysqladmin ping -h localhost -u root -p${DB_ROOT_PASSWORD} --silent 2>/dev/null; then
            print_success "MySQL siap!"
            break
        fi
        COUNT=$((COUNT+1))
        echo -n "."
        sleep 2
    done
    
    if [ $COUNT -eq $MAX_TRIES ]; then
        print_error "MySQL timeout!"
        exit 1
    fi
    
    print_info "Menunggu WordPress siap..."
    sleep 5
    
    print_success "Semua container berjalan!"
}

get_ip_address() {
    # Try to get public IP
    IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    
    if [ -z "$IP" ]; then
        # Fallback to local IP
        IP=$(hostname -I | awk '{print $1}')
    fi
    
    echo $IP
}

print_completion_info() {
    IP=$(get_ip_address)
    
    echo ""
    echo "=========================================="
    print_success "WordPress Lab berhasil diinstall!"
    echo "=========================================="
    echo ""
    echo -e "${GREEN}WordPress URL:${NC}"
    echo -e "  → http://$IP"
    echo -e "  → http://$IP/wp-admin (Admin Panel)"
    echo ""
    echo -e "${GREEN}phpMyAdmin URL:${NC}"
    echo -e "  → http://$IP:8080"
    echo ""
    echo -e "${YELLOW}Database Credentials:${NC}"
    echo -e "  Host: db"
    echo -e "  Database: $DB_NAME"
    echo -e "  User: $DB_USER"
    echo -e "  Password: $DB_PASSWORD"
    echo -e "  Root Password: $DB_ROOT_PASSWORD"
    echo ""
    echo -e "${YELLOW}Upload Limit:${NC} 500 MB"
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo -e "  cd $INSTALL_DIR"
    echo -e "  docker-compose ps          # Cek status"
    echo -e "  docker-compose logs -f     # Lihat logs"
    echo -e "  docker-compose restart     # Restart"
    echo -e "  docker-compose down        # Stop"
    echo -e "  docker-compose down -v     # Stop & hapus data"
    echo "=========================================="
}

# Main execution
main() {
    clear
    echo "=========================================="
    echo "  WordPress Pentesting Lab Setup"
    echo "=========================================="
    echo ""
    
    check_root
    detect_os
    
    # Check and install Docker
    if ! check_docker; then
        install_docker
    fi
    
    # Check and install Docker Compose
    if ! check_docker_compose; then
        install_docker_compose
    fi
    
    create_project_directory
    create_docker_compose
    create_php_config
    configure_firewall
    start_containers
    print_completion_info
    
    echo ""
    print_success "Setup selesai! Silakan akses WordPress di browser."
}

# Run main function
main
