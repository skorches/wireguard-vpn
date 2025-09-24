#!/bin/bash

# WireGuard VPN Server Setup Script
# This script automates the installation and configuration of WireGuard VPN server
# and generates client configuration files with QR codes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
WG_INTERFACE="wg0"
WG_PORT="51820"
WG_CONFIG_DIR="/etc/wireguard"
CLIENT_CONFIG_DIR="/root/wireguard-clients"
SERVER_PRIVATE_KEY_FILE="$WG_CONFIG_DIR/server_private.key"
SERVER_PUBLIC_KEY_FILE="$WG_CONFIG_DIR/server_public.key"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to detect OS and package manager
detect_os() {
    if [[ -f /etc/debian_version ]]; then
        OS="debian"
        PACKAGE_MANAGER="apt"
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        PACKAGE_MANAGER="yum"
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
        PACKAGE_MANAGER="pacman"
    else
        print_error "Unsupported operating system"
        exit 1
    fi
    print_status "Detected OS: $OS"
}

# Function to install WireGuard
install_wireguard() {
    print_header "Installing WireGuard"
    
    case $OS in
        "debian")
            apt update
            apt install -y wireguard wireguard-tools qrencode iptables-persistent
            ;;
        "centos")
            yum install -y epel-release
            yum install -y wireguard-tools qrencode iptables-services
            systemctl enable iptables
            ;;
        "arch")
            pacman -Sy --noconfirm wireguard-tools qrencode iptables
            ;;
    esac
    
    print_status "WireGuard installed successfully"
}

# Function to get server public IP
get_server_ip() {
    SERVER_IP=$(curl -s ipv4.icanhazip.com || curl -s ifconfig.me || curl -s ipinfo.io/ip)
    if [[ -z "$SERVER_IP" ]]; then
        print_error "Could not determine server public IP"
        read -p "Please enter your server's public IP address: " SERVER_IP
    fi
    print_status "Server IP: $SERVER_IP"
}

# Function to get network interface
get_network_interface() {
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$NETWORK_INTERFACE" ]]; then
        print_error "Could not determine network interface"
        ip link show
        read -p "Please enter your network interface (e.g., eth0, ens3): " NETWORK_INTERFACE
    fi
    print_status "Network interface: $NETWORK_INTERFACE"
}

# Function to generate server keys
generate_server_keys() {
    print_header "Generating Server Keys"
    
    mkdir -p $WG_CONFIG_DIR
    cd $WG_CONFIG_DIR
    
    # Generate private key
    wg genkey > $SERVER_PRIVATE_KEY_FILE
    chmod 600 $SERVER_PRIVATE_KEY_FILE
    
    # Generate public key
    cat $SERVER_PRIVATE_KEY_FILE | wg pubkey > $SERVER_PUBLIC_KEY_FILE
    
    SERVER_PRIVATE_KEY=$(cat $SERVER_PRIVATE_KEY_FILE)
    SERVER_PUBLIC_KEY=$(cat $SERVER_PUBLIC_KEY_FILE)
    
    print_status "Server keys generated"
    print_status "Public key: $SERVER_PUBLIC_KEY"
}

# Function to create server configuration
create_server_config() {
    print_header "Creating Server Configuration"
    
    cat > $WG_CONFIG_DIR/$WG_INTERFACE.conf << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = $WG_PORT
SaveConfig = true

# Enable IP forwarding
PostUp = echo 1 > /proc/sys/net/ipv4/ip_forward
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT
PostUp = iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT
PostDown = iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

EOF

    chmod 600 $WG_CONFIG_DIR/$WG_INTERFACE.conf
    print_status "Server configuration created"
}

# Function to enable IP forwarding
enable_ip_forwarding() {
    print_header "Enabling IP Forwarding"
    
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    print_status "IP forwarding enabled"
}

# Function to configure firewall
configure_firewall() {
    print_header "Configuring Firewall"
    
    # Allow WireGuard port
    if command -v ufw &> /dev/null; then
        ufw allow $WG_PORT/udp
        print_status "UFW rule added for port $WG_PORT"
    else
        iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
        print_status "iptables rule added for port $WG_PORT"
    fi
}

# Function to start WireGuard service
start_wireguard() {
    print_header "Starting WireGuard Service"
    
    systemctl enable wg-quick@$WG_INTERFACE
    systemctl start wg-quick@$WG_INTERFACE
    
    print_status "WireGuard service started and enabled"
}

# Function to generate client configuration
generate_client_config() {
    local client_name=$1
    local client_ip=$2
    
    print_header "Generating Client Configuration: $client_name"
    
    mkdir -p $CLIENT_CONFIG_DIR
    
    # Generate client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)
    
    # Create client config file
    cat > $CLIENT_CONFIG_DIR/$client_name.conf << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $client_ip/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Add client to server configuration
    wg set $WG_INTERFACE peer $CLIENT_PUBLIC_KEY allowed-ips $client_ip/32
    wg-quick save $WG_INTERFACE
    
    # Generate QR code
    qrencode -t ansiutf8 < $CLIENT_CONFIG_DIR/$client_name.conf
    qrencode -t png -o $CLIENT_CONFIG_DIR/$client_name.png < $CLIENT_CONFIG_DIR/$client_name.conf
    
    print_status "Client configuration generated: $CLIENT_CONFIG_DIR/$client_name.conf"
    print_status "QR code saved as: $CLIENT_CONFIG_DIR/$client_name.png"
    print_status "Client public key: $CLIENT_PUBLIC_KEY"
    
    echo
    print_status "QR Code for mobile setup:"
    qrencode -t ansiutf8 < $CLIENT_CONFIG_DIR/$client_name.conf
    echo
}

# Function to add a new client
add_client() {
    print_header "Adding New Client"
    
    read -p "Enter client name: " CLIENT_NAME
    
    # Find next available IP
    USED_IPS=$(wg show $WG_INTERFACE allowed-ips | awk '{print $2}' | cut -d'/' -f1 | sort -V)
    for i in {2..254}; do
        IP="10.0.0.$i"
        if ! echo "$USED_IPS" | grep -q "^$IP$"; then
            CLIENT_IP=$IP
            break
        fi
    done
    
    if [[ -z "$CLIENT_IP" ]]; then
        print_error "No available IP addresses"
        exit 1
    fi
    
    generate_client_config "$CLIENT_NAME" "$CLIENT_IP"
}

# Function to remove a client
remove_client() {
    print_header "Removing Client"
    
    echo "Available clients:"
    ls -1 $CLIENT_CONFIG_DIR/*.conf 2>/dev/null | sed 's/.*\///' | sed 's/\.conf$//' || echo "No clients found"
    
    read -p "Enter client name to remove: " CLIENT_NAME
    
    if [[ ! -f "$CLIENT_CONFIG_DIR/$CLIENT_NAME.conf" ]]; then
        print_error "Client configuration not found"
        exit 1
    fi
    
    # Get client public key
    CLIENT_PUBLIC_KEY=$(grep "PrivateKey" $CLIENT_CONFIG_DIR/$CLIENT_NAME.conf | cut -d' ' -f3 | wg pubkey)
    
    # Remove from server
    wg set $WG_INTERFACE peer $CLIENT_PUBLIC_KEY remove
    wg-quick save $WG_INTERFACE
    
    # Remove client files
    rm -f $CLIENT_CONFIG_DIR/$CLIENT_NAME.conf
    rm -f $CLIENT_CONFIG_DIR/$CLIENT_NAME.png
    
    print_status "Client $CLIENT_NAME removed successfully"
}

# Function to show status
show_status() {
    print_header "WireGuard Status"
    
    echo "Server Status:"
    systemctl status wg-quick@$WG_INTERFACE --no-pager
    echo
    
    echo "Active Connections:"
    wg show
    echo
    
    echo "Available Client Configurations:"
    ls -la $CLIENT_CONFIG_DIR/ 2>/dev/null || echo "No client configurations found"
}

# Function to show menu
show_menu() {
    echo
    print_header "WireGuard VPN Management"
    echo "1. Install and setup WireGuard server"
    echo "2. Add new client"
    echo "3. Remove client"
    echo "4. Show status"
    echo "5. Exit"
    echo
}

# Function to check if WireGuard is already installed and configured
is_wireguard_configured() {
    if [[ -f "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]] && systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
        return 0  # Already configured
    else
        return 1  # Not configured
    fi
}

# Function for automatic setup and client addition
auto_setup_and_add_client() {
    print_header "WireGuard Auto Setup & Client Addition"
    
    if is_wireguard_configured; then
        print_status "WireGuard server is already configured and running"
        SERVER_PUBLIC_KEY=$(cat $SERVER_PUBLIC_KEY_FILE)
        get_server_ip
        add_client
    else
        print_status "WireGuard server not found. Starting installation..."
        echo
        
        # Run full installation
        detect_os
        get_server_ip
        get_network_interface
        install_wireguard
        generate_server_keys
        create_server_config
        enable_ip_forwarding
        configure_firewall
        start_wireguard
        
        print_status "WireGuard server setup completed!"
        echo
        print_status "Now creating your first client configuration..."
        echo
        
        # Add first client
        add_client
        
        echo
        print_header "Setup Complete!"
        print_status "Your WireGuard VPN server is now running and your first client is configured."
        print_status "To add more clients in the future, run: $0 add-client"
        print_status "To manage the server, run: $0 menu"
    fi
}

# Main function
main() {
    check_root
    
    case "${1:-auto}" in
        "install")
            detect_os
            get_server_ip
            get_network_interface
            install_wireguard
            generate_server_keys
            create_server_config
            enable_ip_forwarding
            configure_firewall
            start_wireguard
            print_status "WireGuard server setup completed!"
            print_status "Run '$0 add-client' to create client configurations"
            ;;
        "add-client")
            if [[ ! -f "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]]; then
                print_error "WireGuard server not configured. Run '$0 install' first."
                exit 1
            fi
            SERVER_PUBLIC_KEY=$(cat $SERVER_PUBLIC_KEY_FILE)
            get_server_ip
            add_client
            ;;
        "remove-client")
            remove_client
            ;;
        "status")
            show_status
            ;;
        "menu")
            while true; do
                show_menu
                read -p "Choose an option [1-5]: " choice
                case $choice in
                    1)
                        $0 install
                        ;;
                    2)
                        $0 add-client
                        ;;
                    3)
                        $0 remove-client
                        ;;
                    4)
                        $0 status
                        ;;
                    5)
                        print_status "Goodbye!"
                        exit 0
                        ;;
                    *)
                        print_error "Invalid option"
                        ;;
                esac
                echo
                read -p "Press Enter to continue..."
            done
            ;;
        "auto"|*)
            auto_setup_and_add_client
            ;;
    esac
}

# Run main function with all arguments
main "$@"
