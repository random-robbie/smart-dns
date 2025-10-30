# SmartDNS Proxy

A powerful DNS proxy server with intelligent routing and a web-based management interface. Route specific domains to specific DNS servers while using default DNS for everything else.

## Features

- **Service-Oriented Management**: Organize your DNS servers as "services" with beautiful overview cards
- **Visual Dashboard**: See all your SmartDNS services at a glance with domain counts
- **Intelligent DNS Routing**: Route specific domains/subdomains to specific DNS servers
- **Wildcard Support**: Use `*.domain.com` to match all subdomains
- **Domain Discovery Tool**: Analyze any website to automatically discover all domains it uses and test them against SmartDNS
- **Client Tracking**: See which devices are making DNS requests with reverse DNS hostname resolution
- **Intuitive Web Interface**: Easy-to-use tabbed interface with Overview, Services, Domains, Tools, and Logs
- **DNS Request Logs**: View last 200 DNS requests in real-time with dropdown selection for quick domain assignment
- **Quick-Add from Logs**: See unproxied domains and assign them to any service with a dropdown selector
- **Bulk Import**: Import multiple domains at once (newline, comma, or space separated)
- **Import/Export Configuration**: Export your entire configuration as JSON and import on other instances
- **One-Click Domain Assignment**: Add domains to a specific service directly from the overview
- **Multiple DNS Servers**: Pre-configured with SmartDNSProxy and NordVPN SmartDNS
- **Persistent Storage**: All settings persist across Docker rebuilds using volume storage
- **Dual-Stack DNS**: Full IPv4 and IPv6 support for modern networks
- **Network-Wide**: Other machines on your network can use this as their DNS server

## Quick Start

### Option 1: Docker (Recommended)

Docker provides easy deployment with persistent storage and automatic restart capabilities.

**Prerequisites**: Docker installed on your system

**Installation:**

1. **Build the Docker image:**
```bash
docker build -t smartdns-proxy .
```

2. **Run with persistent storage:**
```bash
docker run -d \
  --name smartdns \
  --network host \
  --cap-add=NET_BIND_SERVICE \
  --restart always \
  -v smartdns-data:/data \
  smartdns-proxy
```

The application will start:
- DNS Proxy: `0.0.0.0:53` (UDP - both IPv4 and IPv6)
- Web Interface: `http://localhost:8080`

**Managing the container:**
```bash
# View logs
docker logs smartdns

# Restart the container
docker restart smartdns

# Stop the container
docker stop smartdns

# Remove the container (data persists in volume)
docker rm smartdns
```

**Persistent Storage**: All settings, DNS servers, and domain rules are stored in the `smartdns-data` Docker volume. Your configuration survives container rebuilds and restarts.

### Option 2: Native Go Installation

If you prefer to run without Docker:

**Prerequisites:**
- Go 1.21 or higher
- Root/sudo access (DNS runs on port 53)

**Installation:**

1. **Clone and setup:**
```bash
cd /home/smartdns
go mod download
```

2. **Build the application:**
```bash
go build -o smartdns-proxy
```

3. **Run the proxy (requires sudo for port 53):**
```bash
sudo ./smartdns-proxy
```

The application will start:
- DNS Proxy: `0.0.0.0:53` (UDP)
- Web Interface: `http://localhost:8080`

### Usage

1. **Open the web interface**: Navigate to `http://localhost:8080`

2. **Overview Tab** - Your Dashboard:
   - See total services and domain rules
   - View all your SmartDNS services as beautiful cards
   - Each card shows: service name, DNS servers, and domain count
   - Click "+ Add Domains" on any service card to quickly assign domains
   - Click "View Domains" to see all domains using that service
   - Export/Import your entire configuration as JSON

3. **Services Tab** - Manage Your SmartDNS Services:
   - Add a new service (e.g., "My Netflix Proxy")
   - Enter primary and secondary DNS servers
   - Delete or manage existing services
   - See domain count for each service

4. **Domains Tab** - Manage Domain Rules:
   - Add single domain: Enter `netflix.com`, select service, click "Add Rule"
   - Bulk import: Paste multiple domains, select service, click "Bulk Import"
   - View all active domain rules in a table
   - Rename domains or delete rules as needed

5. **Tools Tab** - Domain Discovery:
   - Enter any website URL (e.g., `https://www.hulu.com`)
   - Select which SmartDNS service to test against
   - Click "Discover Domains" to analyze the website
   - The tool fetches the page and extracts all domains it uses
   - Each domain is tested with both SmartDNS and default DNS
   - Domains that resolve differently are marked as "Recommended"
   - Select domains you want to add and click "Add Selected Domains"
   - Use "Select All Recommended" to quickly configure a streaming service

6. **Logs Tab** - Monitor DNS Requests:
   - See last 200 DNS queries in real-time
   - View client IP addresses with reverse DNS hostnames
   - See which domains are proxied vs. using default DNS
   - For unproxied domains, use the dropdown to select a service and add the rule instantly
   - Logs auto-refresh every 10 seconds

7. **Configure your network**:
   - Point your device's DNS to this server's IP address
   - Or configure your router to use this as the primary DNS

## Pre-configured DNS Servers

The system comes with these DNS servers pre-configured:

- **SmartDNSProxy 1**: 35.178.60.174 (primary), 54.229.171.243 (secondary)
- **SmartDNSProxy 2**: 54.229.171.243 (primary), 35.178.60.174 (secondary)
- **NordVPN SmartDNS**: 103.86.96.103 (primary), 103.86.99.103 (secondary)
- **Default (Cloudflare)**: 1.1.1.1 (primary), 8.8.8.8 (secondary)
- **Default (Google)**: 8.8.8.8 (primary), 1.1.1.1 (secondary)
- **Router**: 192.168.1.1 (primary), 1.1.1.1 (secondary)

You can add/remove DNS servers through the web interface.

## How It Works

1. **DNS Query Received**: Your device sends a DNS query to the proxy
2. **Rule Matching**: The proxy checks if the domain matches any rules
   - Exact match: `netflix.com` matches `netflix.com`
   - Parent domain: `video.netflix.com` matches rule for `netflix.com`
   - Wildcard: `anything.example.com` matches `*.example.com`
3. **Route Query**: Forward to the appropriate DNS server
4. **Return Result**: Send the DNS response back to your device
5. **Log Request**: Every query is logged with timestamp, server used, and proxy status

## DNS Request Logs

The web interface includes a powerful log viewer that tracks the last 200 DNS requests:

### Features
- **Real-time monitoring**: See all DNS queries as they happen
- **Client tracking**: View which devices are making requests with their IP addresses and resolved hostnames
- **Proxy status**: Instantly see which domains are using custom DNS vs. default DNS
- **Quick-add with dropdown**: For unproxied domains, select a SmartDNS service from the dropdown to add it instantly
- **Auto-refresh**: Logs update automatically every 10 seconds
- **Response time**: See how long each query took
- **Query type**: View A, AAAA, CNAME, and other DNS query types

### Usage Tips
1. **Find missing domains**: Browse through your logs to see what domains you're accessing
2. **Quick setup**: Watch Netflix/Hulu/etc., then check the logs and add all their domains by selecting a service from the dropdown
3. **Troubleshooting**: Verify that your rules are working by checking if domains show "Proxied: Yes"
4. **Performance**: Monitor response times to ensure your DNS servers are fast
5. **Device monitoring**: See which devices on your network are making DNS requests

## Configuration

### Persistent Storage (Docker)

When running with Docker, all data is stored in the `smartdns-data` volume at `/data/smartdns.db` inside the container. This ensures your settings survive container rebuilds.

**Backup your data:**
```bash
docker run --rm -v smartdns-data:/data -v $(pwd):/backup alpine tar czf /backup/smartdns-backup.tar.gz /data
```

**Restore from backup:**
```bash
docker run --rm -v smartdns-data:/data -v $(pwd):/backup alpine tar xzf /backup/smartdns-backup.tar.gz -C /
```

**Inspect the volume:**
```bash
docker volume inspect smartdns-data
```

**Remove the volume (WARNING: deletes all data):**
```bash
docker volume rm smartdns-data
```

### Environment Variables

- `DB_PATH`: Set the database file path (default: `/data/smartdns.db`)

Example:
```bash
docker run -d \
  --name smartdns \
  --network host \
  -e DB_PATH=/custom/path/smartdns.db \
  -v smartdns-data:/custom/path \
  smartdns-proxy
```

### Change Default DNS Servers

Edit `internal/proxy/proxy.go:21-22` to change the fallback DNS servers:
```go
defaultServers: []string{"1.1.1.1:53", "8.8.8.8:53"},
```

### Change Ports

- DNS Port: Edit `main.go:41` - default is `:53`
- Web Port: Edit `main.go:50` - default is `:8080`

## Network Setup

### On macOS
```bash
# System Preferences > Network > Advanced > DNS
# Add: <your-server-ip>
```

### On Linux
```bash
# Edit /etc/resolv.conf
sudo nano /etc/resolv.conf
# Add: nameserver <your-server-ip>
```

### On Windows
```
Control Panel > Network and Internet > Network Connections
Right-click adapter > Properties > Internet Protocol Version 4
Use the following DNS server addresses: <your-server-ip>
```

### On Your Router
Configure your router's DNS settings to point to this server. This will automatically configure all devices on your network.

## Running as a Service

### Docker (Recommended)

The Docker deployment includes automatic restart with `--restart always`. The container will:
- ✅ **Automatically restart on failure** (if the container crashes)
- ✅ **Start on system boot** (even after server reboots)
- ✅ **Restart even if manually stopped** (until explicitly removed)

**Check container status:**
```bash
docker ps -a | grep smartdns
```

**View logs:**
```bash
docker logs -f smartdns
```

**Update to latest version:**
```bash
# Rebuild image
docker build -t smartdns-proxy .

# Stop and remove old container
docker stop smartdns
docker rm smartdns

# Start new container (data persists in volume)
docker run -d \
  --name smartdns \
  --network host \
  --cap-add=NET_BIND_SERVICE \
  --restart unless-stopped \
  -v smartdns-data:/data \
  smartdns-proxy
```

### systemd (Linux - Native Installation)

For native Go installations, create `/etc/systemd/system/smartdns-proxy.service`:
```ini
[Unit]
Description=SmartDNS Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/smartdns
ExecStart=/home/smartdns/smartdns-proxy
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable smartdns-proxy
sudo systemctl start smartdns-proxy
sudo systemctl status smartdns-proxy
```

## Troubleshooting

### Docker: Container Won't Start

Check the logs for errors:
```bash
docker logs smartdns
```

Verify port 53 is not in use:
```bash
sudo lsof -i :53
# or
sudo netstat -tulpn | grep :53
```

### Docker: Settings Not Persisting

Ensure you're using the volume mount `-v smartdns-data:/data` when running the container. If you forgot the volume:

1. Stop the container: `docker stop smartdns`
2. Remove it: `docker rm smartdns`
3. Start with volume: Use the run command from Quick Start

### Port 53 Already in Use

If another DNS service is running:
```bash
# Check what's using port 53
sudo lsof -i :53

# On Ubuntu/Debian, disable systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
```

### Permission Denied on Port 53

Port 53 requires root privileges. With Docker, use `--cap-add=NET_BIND_SERVICE`. For native installation:
```bash
sudo ./smartdns-proxy
```

### Can't Access Web Interface

Check the API server is running:
```bash
# Docker
docker logs smartdns | grep "Starting API"

# Native
curl http://localhost:8080/api/servers
```

### Domain Discovery Tool Not Finding Domains

If the domain discovery tool shows no results:
1. Verify the URL is accessible from your server
2. Check if the website blocks automated requests
3. Try accessing the URL directly: `curl -L https://example.com`
4. Some websites may require JavaScript - the tool only analyzes HTML

### Streaming Site Not Working After Adding Domains

1. Use the **Domain Discovery Tool** to automatically find all required domains
2. Check the **Logs tab** to see which domains the site is using
3. Add missing domains using the dropdown in the logs
4. Clear your browser cache and try again
5. Some sites (like Netflix) may require specific regional DNS servers

## Example Use Cases

### Stream Content with SmartDNS
Route streaming services through SmartDNS to access region-restricted content:

**Quick Setup with Domain Discovery:**
1. Go to the **Tools** tab
2. Enter `https://www.hulu.com` (or Netflix, Disney+, etc.)
3. Select your SmartDNS service
4. Click "Discover Domains"
5. Click "Select All Recommended"
6. Click "Add Selected Domains"
7. Done! All necessary domains are configured automatically

**Manual Setup:**
```
netflix.com -> SmartDNSProxy
hulu.com -> SmartDNSProxy
*.disneyplus.com -> SmartDNSProxy
```

### Privacy-Focused Routing
Route specific domains through NordVPN:
```
*.bank.com -> NordVPN SmartDNS
*.private-site.com -> NordVPN SmartDNS
```

### Development Setup
Route local development domains to your router:
```
*.local -> Router (192.168.1.1)
*.dev -> Router (192.168.1.1)
```

### Complete Workflow Example
Setting up a streaming service from scratch:

1. **Create the service** (Services tab):
   - Name: "Hulu US"
   - Primary DNS: 35.178.60.174
   - Secondary DNS: 54.229.171.243

2. **Discover domains** (Tools tab):
   - URL: https://www.hulu.com
   - Service: Hulu US
   - Let the tool analyze and find all domains

3. **Monitor and refine** (Logs tab):
   - Watch the logs while using Hulu
   - Add any missing domains using the dropdown

4. **Export your config** (Overview tab):
   - Click "Export Config" to save your setup
   - Import on other SmartDNS instances

## Project Structure

```
smartdns-proxy/
├── main.go                 # Application entry point
├── internal/
│   ├── api/
│   │   └── api.go         # REST API server
│   ├── db/
│   │   └── db.go          # Database operations
│   └── proxy/
│       └── proxy.go       # DNS proxy logic
├── web/
│   └── index.html         # Web management interface
├── go.mod                 # Go dependencies
└── README.md              # This file
```

## License

MIT License - Feel free to use and modify as needed.

## Contributing

Contributions welcome! Feel free to submit issues and pull requests.
