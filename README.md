# WireGuard VPN Server Setup Script

A comprehensive bash script to automatically install, configure, and manage a WireGuard VPN server on your VPS with client configuration generation and QR codes.

## Features

- 🚀 **Automated Installation**: One-command setup for WireGuard server
- 🔐 **Secure Key Generation**: Automatic generation of server and client keys
- 📱 **QR Code Support**: Generate QR codes for easy mobile client setup
- 🌐 **Multi-OS Support**: Works on Debian/Ubuntu, CentOS/RHEL, and Arch Linux
- 🔧 **Client Management**: Easy add/remove clients with IP management
- 🛡️ **Firewall Configuration**: Automatic firewall rules setup
- 📊 **Status Monitoring**: View server status and active connections

## Prerequisites

- Root access to your VPS
- Supported OS: Debian/Ubuntu, CentOS/RHEL, or Arch Linux
- Internet connection for package installation

## Quick Start

1. **Download the script:**
   ```bash
   wget https://raw.githubusercontent.com/yourusername/wireguard-setup/main/wireguard-setup.sh
   # or
   curl -O https://raw.githubusercontent.com/yourusername/wireguard-setup/main/wireguard-setup.sh
   ```

2. **Make it executable:**
   ```bash
   chmod +x wireguard-setup.sh
   ```

3. **Run the installation:**
   ```bash
   sudo ./wireguard-setup.sh install
   ```

4. **Add your first client:**
   ```bash
   sudo ./wireguard-setup.sh add-client
   ```

## Usage

### Interactive Menu
Run the script without arguments to access the interactive menu:
```bash
sudo ./wireguard-setup.sh
```

### Command Line Options

#### Install WireGuard Server
```bash
sudo ./wireguard-setup.sh install
```
This will:
- Detect your OS and install WireGuard
- Generate server keys
- Configure the server
- Set up firewall rules
- Start the WireGuard service

#### Add a New Client
```bash
sudo ./wireguard-setup.sh add-client
```
This will:
- Prompt for client name
- Generate client keys
- Create client configuration file
- Generate QR code for mobile setup
- Add client to server configuration

#### Remove a Client
```bash
sudo ./wireguard-setup.sh remove-client
```

#### Check Status
```bash
sudo ./wireguard-setup.sh status
```

## Configuration Details

### Server Configuration
- **Interface**: `wg0`
- **Port**: `51820` (UDP)
- **Server IP**: `10.0.0.1/24`
- **Client IP Range**: `10.0.0.2-254`

### File Locations
- **Server Config**: `/etc/wireguard/wg0.conf`
- **Server Keys**: `/etc/wireguard/server_*.key`
- **Client Configs**: `/root/wireguard-clients/`

## Client Setup

### Desktop Clients (Windows/macOS/Linux)
1. Install WireGuard client from [wireguard.com](https://www.wireguard.com/install/)
2. Import the generated `.conf` file
3. Connect to the VPN

### Mobile Clients (iOS/Android)
1. Install WireGuard app from App Store/Play Store
2. Scan the QR code displayed after client creation
3. Connect to the VPN

### Manual Configuration
If you prefer manual setup, use the generated configuration file:

```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.0.0.X/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = <server_public_key>
Endpoint = <server_ip>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

## Firewall Configuration

The script automatically configures firewall rules. If you're using a custom firewall setup, ensure these ports are open:

- **UDP 51820**: WireGuard traffic
- **Allow forwarding**: Between WireGuard interface and main network interface

### Manual Firewall Rules (if needed)
```bash
# UFW
ufw allow 51820/udp

# iptables
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

## Troubleshooting

### Common Issues

1. **"Permission denied" error**
   - Make sure you're running as root: `sudo ./wireguard-setup.sh`

2. **"Could not determine server IP"**
   - The script will prompt you to enter your server's public IP manually

3. **Clients can't connect**
   - Check if port 51820/UDP is open in your firewall
   - Verify your VPS provider allows UDP traffic

4. **No internet access through VPN**
   - Ensure IP forwarding is enabled: `cat /proc/sys/net/ipv4/ip_forward` should return `1`
   - Check NAT rules: `iptables -t nat -L`

### Checking Logs
```bash
# WireGuard service status
systemctl status wg-quick@wg0

# WireGuard interface status
wg show

# System logs
journalctl -u wg-quick@wg0 -f
```

### Manual Service Management
```bash
# Start WireGuard
systemctl start wg-quick@wg0

# Stop WireGuard
systemctl stop wg-quick@wg0

# Restart WireGuard
systemctl restart wg-quick@wg0

# Enable auto-start
systemctl enable wg-quick@wg0
```

## Security Considerations

- **Keep private keys secure**: Never share server or client private keys
- **Regular updates**: Keep WireGuard and your system updated
- **Client management**: Remove unused clients promptly
- **Firewall**: Only open necessary ports
- **Monitoring**: Regularly check active connections

## Advanced Configuration

### Custom Port
To use a different port, edit the script and change:
```bash
WG_PORT="51820"  # Change to your desired port
```

### Custom IP Range
To use a different IP range, modify the server configuration:
```bash
# In create_server_config() function
Address = 192.168.100.1/24  # Change to your desired range
```

### DNS Servers
To use different DNS servers for clients, modify:
```bash
DNS = 1.1.1.1, 1.0.0.1  # Cloudflare DNS
# or
DNS = 9.9.9.9, 149.112.112.112  # Quad9 DNS
```

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this script.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This script is provided as-is for educational and legitimate networking purposes. Always ensure you have proper authorization before setting up VPN services on any server.
