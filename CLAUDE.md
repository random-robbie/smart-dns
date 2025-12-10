# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SmartDNS Proxy is a DNS proxy server with SOCKS5 proxy support, intelligent routing, and web-based management. It allows routing specific domains to specific DNS servers while using default DNS for everything else, and can route traffic through SOCKS proxies based on domain rules. The application is containerized with Docker and consists of five main components that run concurrently:

1. **DNS Proxy Server** (port 53) - Dual-stack (IPv4+IPv6) DNS server that handles queries and routes them based on domain rules
2. **DNS-over-TLS Server** (port 853) - Encrypted DNS server for Private DNS support on Android and other devices
3. **SOCKS5 Proxy Server** (port 1080) - SOCKS5 proxy server that routes connections through upstream SOCKS proxies based on domain rules
4. **REST API Server** (port 8080) - Provides backend API for managing DNS servers, SOCKS proxies, and domain rules
5. **Web Interface** - Modern single-page application with dark mode, domain discovery tools, SOCKS proxy management, and real-time logging

## Build & Run Commands

### Docker (Recommended)
```bash
# Build Docker image
docker build -t smartdns-proxy .

# Run with persistent storage and auto-restart
docker run -d \
  --name smartdns \
  --network host \
  --cap-add=NET_BIND_SERVICE \
  --restart always \
  -v smartdns-data:/data \
  smartdns-proxy

# Generate TLS certificates for DNS-over-TLS (first time only)
docker exec smartdns ./generate-certs.sh

# Restart to enable DNS-over-TLS after generating certificates
docker restart smartdns

# View logs
docker logs smartdns -f

# Stop and remove
docker stop smartdns && docker rm smartdns

# Rebuild after code changes
docker stop smartdns && docker rm smartdns
docker build -t smartdns-proxy .
docker run -d --name smartdns --network host --cap-add=NET_BIND_SERVICE --restart always -v smartdns-data:/data smartdns-proxy
```

### Development (Direct Go)
```bash
# Install dependencies
go mod download

# Build the binary
CGO_ENABLED=1 go build -o smartdns-proxy

# Run (requires sudo for port 53)
sudo ./smartdns-proxy

# Set custom database path
DB_PATH=/custom/path/smartdns.db sudo ./smartdns-proxy
```

### Testing
DNS queries can be tested using `dig` or `nslookup`:
```bash
# Test standard DNS (UDP)
dig @192.168.1.82 example.com
dig @192.168.1.82 -t AAAA example.com  # IPv6 test
nslookup example.com 192.168.1.82

# Test DNS-over-TLS (requires kdig from knot-dnsutils)
kdig -d @192.168.1.82 +tls example.com

# Test SOCKS5 proxy
curl -x socks5://192.168.1.82:1080 https://example.com
# With authentication
curl -x socks5://username:password@192.168.1.82:1080 https://example.com
```

The web interface is accessible at `http://192.168.1.82:8080` when running (replace with your server IP).

### Configuring Private DNS on Android
1. Generate certificates: `docker exec smartdns ./generate-certs.sh`
2. Copy `/data/certs/dns.crt` from the container to your phone
3. Install the certificate: Settings > Security > Install from storage
4. Enable Private DNS: Settings > Network & internet > Private DNS > Private DNS provider hostname
5. Enter your server's IP address (e.g., `192.168.1.82`)

## Architecture

### Application Flow
`main.go` initializes five concurrent components:
1. **Database (SQLite)** - Stored in `/data/smartdns.db` for persistence across container rebuilds
2. **DNSLogger** - Thread-safe in-memory circular buffer for last 200 DNS requests
3. **DNS Proxy goroutines** - Multiple DNS servers:
   - IPv4 UDP server on `0.0.0.0:53`
   - IPv6 UDP server on `[::]:53`
   - DNS-over-TLS TCP server on `0.0.0.0:853` (if certificates exist)
4. **SOCKS5 Proxy goroutine** - TCP server on `0.0.0.0:1080`
5. **API Server goroutine** - HTTP server on `:8080`

### Data Persistence
- Database location: `/data/smartdns.db` (configurable via `DB_PATH` env var)
- Docker volume: `smartdns-data:/data` ensures settings persist across container rebuilds
- All DNS servers, SOCKS proxies, domain rules, and configuration survive restarts

### DNS Query Resolution (`internal/proxy/proxy.go`)
The proxy uses hierarchical domain matching with dual-stack support:
1. **Exact match**: Checks if domain has a specific rule (e.g., `netflix.com`)
2. **Parent domain match**: Recursively checks parent domains (e.g., `video.netflix.com` → `netflix.com`)
3. **Wildcard match**: Checks for wildcard rules in database (e.g., `*.example.com`)
4. **Default fallback**: Uses default DNS servers (Cloudflare 1.1.1.1, Google 8.8.8.8)

Each query is forwarded to the appropriate DNS server and logged with timing information, client IP, and hostname.

### Database Schema (`internal/db/db.go`)
SQLite database with three tables:
- `dns_servers`: Stores DNS server configurations (name, primary, secondary IPs)
- `socks_proxies`: Stores SOCKS5 proxy configurations (name, host, port, username, password, enabled)
- `domain_rules`: Maps domains to DNS servers and optionally SOCKS proxies (includes index on domain column, foreign keys to both dns_servers and socks_proxies)

Six default DNS servers are pre-configured on first run, including SmartDNSProxy, NordVPN SmartDNS, Cloudflare, and Google DNS.

### SOCKS5 Proxy Server (`internal/socks/socks.go`)
The SOCKS5 proxy server provides intelligent traffic routing through upstream proxies:
1. **Client connection** - Accepts SOCKS5 connections on port 1080
2. **Domain matching** - Extracts target domain from CONNECT requests
3. **Proxy lookup** - Checks domain rules database for matching SOCKS proxy configuration
4. **Upstream connection** - If a proxy is configured for the domain, connects through the upstream SOCKS proxy; otherwise makes direct connection
5. **Authentication** - Supports both no-auth and username/password authentication for upstream proxies
6. **Bidirectional relay** - Forwards data between client and target using goroutines

The proxy supports hierarchical domain matching (exact, parent, wildcard) and can chain through multiple SOCKS proxies.

### DNS Logging (`internal/logs/logs.go`)
Thread-safe in-memory circular buffer that stores the last 200 DNS requests. Uses `sync.RWMutex` for concurrent access. Logs include:
- Domain, query type (A, AAAA, etc.)
- Server used, proxy status, response time
- Client IP and hostname (via reverse DNS lookup)

### API Endpoints (`internal/api/api.go`)
REST API using gorilla/mux router:
- `/api/servers` - CRUD for DNS server configurations (GET, POST, PUT, DELETE)
- `/api/proxies` - CRUD for SOCKS proxy configurations (GET, POST, PUT, DELETE)
- `/api/rules` - CRUD for domain rules with optional proxy assignment (GET, POST, DELETE)
- `/api/rules/bulk` - Bulk import multiple domains
- `/api/logs` - Retrieve DNS logs, clear logs, get unproxied domains
- `/api/export` - Export configuration as JSON
- `/api/import` - Import configuration from JSON
- `/api/system/ip` - Get local server IP for DNS configuration
- `/api/tools/discover` - Analyze website and discover all required domains

### Web Interface (`web/index.html`)
Modern single-page application with:
- **Dark/Light mode** - Theme preference stored in localStorage
- **Dashboard** - Overview with stats and service cards
- **SOCKS Proxies** - Manage SOCKS5 proxies with enable/disable toggle
- **Services** - Manage DNS servers with rename capability
- **Domains** - Add/remove domain rules with bulk import
- **Request Logs** - Real-time DNS query log with auto-refresh and dropdown for quick-add
- **Tools** - Domain discovery tool for analyzing websites
- **Settings** - Network info, import/export, backup/restore

## Key Configuration Points

### Port Configuration
- DNS IPv4: `internal/proxy/proxy.go:42` - `0.0.0.0:53` (UDP)
- DNS IPv6: `internal/proxy/proxy.go:53` - `[::]:53` (UDP)
- DNS-over-TLS: `internal/proxy/proxy.go:104` - `0.0.0.0:853` (TCP-TLS)
- SOCKS5 proxy: `main.go:51` - `0.0.0.0:1080` (TCP)
- Web/API port: `main.go:60` - `:8080` (HTTP)

### Default DNS Servers
- Fallback DNS: `internal/proxy/proxy.go:26` - default `["1.1.1.1:53", "8.8.8.8:53"]`
- Pre-configured servers: `internal/db/db.go:69-80`

### Data Storage
- Database path: `main.go:18-24` - default `/data/smartdns.db`
- Override with env var: `DB_PATH=/custom/path/db.sqlite`
- Docker volume mount: `-v smartdns-data:/data`

### TLS Certificates (DNS-over-TLS)
- Certificate path: default `/data/certs/dns.crt`
- Private key path: default `/data/certs/dns.key`
- Override with env vars: `TLS_CERT_PATH` and `TLS_KEY_PATH`
- Generate certificates: `./generate-certs.sh`

### Log Capacity
- DNS log buffer size: `main.go:30` - default 200 requests

## New Features

### SOCKS5 Proxy Support
The system now includes a full SOCKS5 proxy server with intelligent routing:
- **Server**: Listens on port 1080 for SOCKS5 connections
- **Domain-based routing**: Routes traffic through different upstream SOCKS proxies based on domain rules
- **Authentication**: Supports both no-auth and username/password authentication for upstream proxies
- **Web management**: Add, edit, enable/disable, and delete proxies via the web UI
- **Direct fallback**: Domains without proxy rules use direct connections

**Use Cases**:
- Route streaming services (Netflix, Hulu) through specific proxies while using direct connection for everything else
- Chain proxies for additional privacy
- Bypass geo-restrictions on a per-domain basis
- Test proxy configurations without changing system-wide settings

**Configuration**: Add SOCKS proxies in the web UI under "SOCKS Proxies" tab, then assign them to domains in the "Domains" tab.

### Domain Discovery Tool
The domain discovery tool (`/api/tools/discover`) analyzes a website and automatically:
1. Fetches the website HTML
2. Extracts all domains from links, scripts, stylesheets, and resources
3. Tests each domain with both SmartDNS and default DNS
4. Compares IP addresses to identify which domains resolve differently
5. Recommends domains that should use SmartDNS

Implementation in `internal/api/api.go:469-675` includes:
- HTML parsing with regex patterns
- DNS resolution testing
- IP comparison logic
- Domain validation

### Client Tracking
DNS requests now track client information:
- Client IP address (from UDP source)
- Client hostname (via reverse DNS lookup)
- Displayed in logs with tooltip showing IP when hovering over hostname

### Import/Export Configuration
- Export: Downloads JSON with all DNS servers and domain rules
- Import: Uploads JSON and restores configuration
- Server ID mapping ensures rules reference correct servers after import

## Common Development Scenarios

### Adding a New DNS Provider
1. Add to `internal/db/db.go` in `InitializeDefaultServers()` or via web UI
2. Format: `{name, primary_ip, secondary_ip}`
3. Database automatically assigns ID

### Modifying DNS Resolution Logic
The domain matching algorithm is in `internal/proxy/proxy.go:111-158` (`findDNSServers` function). This handles:
- Exact domain matching
- Parent domain matching (recursive)
- Wildcard matching (`*.domain.com`)
- Default fallback

### Extending the API
1. Add route in `internal/api/api.go:setupRoutes()`
2. Implement handler function following existing patterns
3. All handlers receive `*APIServer` receiver with database and logger access
4. Use gorilla/mux for routing and parameter extraction

### Adding New Web UI Features
The web interface (`web/index.html`) is a single-page application:
- Add new tab: Update tabs HTML and add corresponding `tab-content` div
- Add JavaScript function: Use existing patterns with `async/await` for API calls
- Styling: Uses CSS variables for theming (supports dark/light mode)
- Tab switching: Use `switchTab(tabName, event)` function

## Docker Deployment

### Building for Alpine Linux
The Dockerfile uses multi-stage build:
1. **Builder stage**: golang:1.21-alpine with build tools
2. **Runtime stage**: alpine:latest with only runtime dependencies
3. CGO enabled for SQLite support
4. `CGO_CFLAGS="-D_LARGEFILE64_SOURCE"` required for musl libc compatibility

### Network Configuration
- `--network host` - Uses host networking for DNS (port 53)
- `--cap-add=NET_BIND_SERVICE` - Allows binding to privileged ports
- Alternative: Use `-p 53:53/udp -p 53:53/udp6 -p 8080:8080` without host network

### Volume Management
```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect smartdns-data

# Backup volume
docker run --rm -v smartdns-data:/data -v $(pwd):/backup alpine tar czf /backup/smartdns-backup.tar.gz /data

# Restore volume
docker run --rm -v smartdns-data:/data -v $(pwd):/backup alpine tar xzf /backup/smartdns-backup.tar.gz
```

## Dependencies
- `github.com/miekg/dns` - DNS protocol implementation
- `github.com/gorilla/mux` - HTTP router
- `github.com/mattn/go-sqlite3` - SQLite database driver (requires CGO)

## Important Notes
- Port 53 requires CAP_NET_BIND_SERVICE capability in Docker or root privileges
- Port 853 (DNS-over-TLS) also requires CAP_NET_BIND_SERVICE or root privileges
- The application handles SIGTERM/SIGINT for graceful shutdown
- Database file `/data/smartdns.db` is created on first run
- All database operations use foreign key cascades - deleting a DNS server deletes all its domain rules
- CORS is enabled on API for development purposes
- Dual-stack DNS (IPv4 + IPv6) ensures compatibility with all clients
- Reverse DNS lookups for hostname resolution may add latency to first query from each client
- DNS-over-TLS is automatically enabled when certificates are present in `/data/certs/`
- Self-signed certificates need to be installed on client devices for Private DNS to work
