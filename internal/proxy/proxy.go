package proxy

import (
	"context"
	"crypto/tls"
	"database/sql"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"smartdns-proxy/internal/db"
	"smartdns-proxy/internal/logs"
)

type DNSProxy struct {
	db             *sql.DB
	addr           string
	defaultServers []string
	logger         *logs.DNSLogger
	hostnameCache  map[string]string
	cacheMutex     sync.RWMutex
}

func NewDNSProxy(database *sql.DB, addr string, logger *logs.DNSLogger) *DNSProxy {
	return &DNSProxy{
		db:             database,
		addr:           addr,
		defaultServers: []string{"1.1.1.1:53", "8.8.8.8:53"},
		logger:         logger,
		hostnameCache:  make(map[string]string),
	}
}

func (p *DNSProxy) Start() error {
	dns.HandleFunc(".", p.handleDNSRequest)

	// Start IPv4 UDP server
	server4 := &dns.Server{Addr: p.addr, Net: "udp4"}
	go func() {
		log.Println("Starting IPv4 DNS server on", p.addr)
		if err := server4.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start IPv4 DNS server: %v", err)
		}
	}()

	// Start IPv6 UDP server to handle IPv6 DNS requests
	// This allows phones using IPv6 to resolve domains
	ipv6Addr := "[::]:53"
	server6 := &dns.Server{Addr: ipv6Addr, Net: "udp6"}
	go func() {
		log.Println("Starting IPv6 DNS server on", ipv6Addr)
		if err := server6.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start IPv6 DNS server: %v", err)
		}
	}()

	// Start DNS-over-TLS server on port 853 if certificates are available
	certPath := os.Getenv("TLS_CERT_PATH")
	keyPath := os.Getenv("TLS_KEY_PATH")

	// Default paths if not specified
	if certPath == "" {
		certPath = "/data/certs/dns.crt"
	}
	if keyPath == "" {
		keyPath = "/data/certs/dns.key"
	}

	// Check if certificates exist
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			log.Println("TLS certificates found, starting DNS-over-TLS server...")
			go p.startTLSServer(certPath, keyPath)
		} else {
			log.Printf("TLS key not found at %s, skipping DNS-over-TLS", keyPath)
		}
	} else {
		log.Printf("TLS certificate not found at %s, skipping DNS-over-TLS", certPath)
		log.Println("To enable DNS-over-TLS, run: ./generate-certs.sh")
	}

	// Keep main goroutine alive
	select {}
}

func (p *DNSProxy) startTLSServer(certPath, keyPath string) {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Printf("Failed to load TLS certificates: %v", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Start DNS-over-TLS server on port 853
	dotAddr := "0.0.0.0:853"
	serverTLS := &dns.Server{
		Addr:      dotAddr,
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting DNS-over-TLS server on %s", dotAddr)
	if err := serverTLS.ListenAndServe(); err != nil {
		log.Printf("Failed to start DNS-over-TLS server: %v", err)
	}
}

func (p *DNSProxy) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = false

	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	queryType := dns.TypeToString[question.Qtype]

	// Get client IP address (works for both UDP and TCP/TLS)
	clientIP := ""
	clientHost := ""
	if addr := w.RemoteAddr(); addr != nil {
		switch v := addr.(type) {
		case *net.UDPAddr:
			clientIP = v.IP.String()
		case *net.TCPAddr:
			clientIP = v.IP.String()
		}

		if clientIP != "" {
			// Check cache first
			p.cacheMutex.RLock()
			cachedHost, found := p.hostnameCache[clientIP]
			p.cacheMutex.RUnlock()

			if found {
				clientHost = cachedHost
			} else {
				// Do reverse DNS lookup with timeout (non-blocking)
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()

				// Use a goroutine with channel to handle timeout
				resultChan := make(chan string, 1)
				go func() {
					names, err := net.LookupAddr(clientIP)
					if err == nil && len(names) > 0 {
						resultChan <- strings.TrimSuffix(names[0], ".")
					} else {
						resultChan <- ""
					}
				}()

				select {
				case hostname := <-resultChan:
					if hostname != "" {
						clientHost = hostname
						// Cache the result
						p.cacheMutex.Lock()
						p.hostnameCache[clientIP] = hostname
						p.cacheMutex.Unlock()
					}
				case <-ctx.Done():
					// Timeout - continue without hostname
					clientHost = ""
				}
			}
		}
	}

	log.Printf("DNS Query: %s (Type: %s) from %s", domain, queryType, clientIP)

	// Find matching DNS server for this domain
	targetServers, isProxied, serverName := p.findDNSServers(domain)

	// Forward the query
	response := p.forwardQuery(r, targetServers)

	// Calculate response time
	responseTime := time.Since(startTime).Milliseconds()

	// Log the request
	if p.logger != nil {
		p.logger.Log(domain, queryType, serverName, isProxied, responseTime, clientIP, clientHost)
	}

	if response != nil {
		err := w.WriteMsg(response)
		if err != nil {
			log.Printf("ERROR: Failed to send response to %s for %s: %v", clientIP, domain, err)
		} else {
			log.Printf("SUCCESS: Sent response to %s for %s (%d answers)", clientIP, domain, len(response.Answer))
		}
	} else {
		// If forwarding failed, return SERVFAIL
		log.Printf("ERROR: No response from upstream for %s from %s", domain, clientIP)
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
	}
}

// addPortIfMissing adds :53 to an IP address if no port is specified
func addPortIfMissing(addr string) string {
	if strings.Contains(addr, ":") {
		return addr
	}
	return addr + ":53"
}

func (p *DNSProxy) findDNSServers(domain string) ([]string, bool, string) {
	// Check for exact match or parent domain match
	checkDomain := domain
	for {
		rule, err := db.GetDomainRule(p.db, checkDomain)
		if err == nil && rule != nil {
			// Found a rule, get the DNS server
			server, err := db.GetDNSServer(p.db, rule.ServerID)
			if err == nil && server != nil {
				servers := []string{addPortIfMissing(server.Primary)}
				if server.Secondary != "" {
					servers = append(servers, addPortIfMissing(server.Secondary))
				}
				log.Printf("Using custom DNS for %s: %v", domain, servers)
				return servers, true, server.Name
			}
		}

		// Try parent domain (e.g., video.netflix.com -> netflix.com -> com)
		parts := strings.SplitN(checkDomain, ".", 2)
		if len(parts) < 2 {
			break
		}
		checkDomain = parts[1]
	}

	// Check for wildcard rules (e.g., *.netflix.com)
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		wildcardDomain := "*." + strings.Join(parts[i:], ".")
		rule, err := db.GetDomainRule(p.db, wildcardDomain)
		if err == nil && rule != nil {
			server, err := db.GetDNSServer(p.db, rule.ServerID)
			if err == nil && server != nil {
				servers := []string{addPortIfMissing(server.Primary)}
				if server.Secondary != "" {
					servers = append(servers, addPortIfMissing(server.Secondary))
				}
				log.Printf("Using custom DNS for %s (wildcard %s): %v", domain, wildcardDomain, servers)
				return servers, true, server.Name
			}
		}
	}

	// Use default servers
	log.Printf("Using default DNS for %s: %v", domain, p.defaultServers)
	return p.defaultServers, false, "Default DNS"
}

func (p *DNSProxy) forwardQuery(query *dns.Msg, servers []string) *dns.Msg {
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	for _, server := range servers {
		response, _, err := client.Exchange(query, server)
		if err != nil {
			log.Printf("Failed to query %s: %v", server, err)
			continue
		}

		if response != nil {
			return response
		}
	}

	return nil
}
