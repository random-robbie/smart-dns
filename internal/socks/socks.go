package socks

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"smartdns-proxy/internal/db"
)

const (
	socks5Version = 0x05
	socksNoAuth   = 0x00
	socksUserPass = 0x02
	socksConnect  = 0x01
	socksIPv4     = 0x01
	socksDomain   = 0x03
	socksIPv6     = 0x04
)

type SOCKSServer struct {
	db       *sql.DB
	addr     string
	listener net.Listener
}

func NewSOCKSServer(database *sql.DB, addr string) *SOCKSServer {
	return &SOCKSServer{
		db:   database,
		addr: addr,
	}
}

func (s *SOCKSServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS server: %w", err)
	}

	s.listener = listener
	log.Printf("SOCKS5 proxy listening on %s", s.addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *SOCKSServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// resolveViaLocalDNS resolves a domain using the local DNS proxy on port 53
// This ensures SOCKS connections follow the same DNS rules as direct DNS queries
func (s *SOCKSServer) resolveViaLocalDNS(domain string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			// Use local DNS proxy instead of system resolver
			return d.DialContext(ctx, network, "127.0.0.1:53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	log.Printf("SOCKS DNS lookup for %s via local DNS proxy: %v", domain, ips)
	return ips, nil
}

func (s *SOCKSServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set timeout for initial handshake
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 greeting
	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil {
		log.Printf("Failed to read greeting: %v", err)
		return
	}

	if n < 2 || buf[0] != socks5Version {
		log.Printf("Invalid SOCKS version: %d", buf[0])
		return
	}

	// No authentication required for now
	_, err = clientConn.Write([]byte{socks5Version, socksNoAuth})
	if err != nil {
		log.Printf("Failed to send auth response: %v", err)
		return
	}

	// Read connection request
	n, err = clientConn.Read(buf)
	if err != nil {
		log.Printf("Failed to read request: %v", err)
		return
	}

	if n < 7 || buf[0] != socks5Version {
		log.Printf("Invalid request")
		return
	}

	cmd := buf[1]
	if cmd != socksConnect {
		// Only support CONNECT command
		s.sendReply(clientConn, 0x07) // Command not supported
		return
	}

	// Parse target address
	addressType := buf[3]
	var targetAddr string
	var targetDomain string
	var port uint16

	switch addressType {
	case socksIPv4:
		if n < 10 {
			s.sendReply(clientConn, 0x01) // General failure
			return
		}
		targetAddr = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])

	case socksDomain:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			s.sendReply(clientConn, 0x01) // General failure
			return
		}
		targetDomain = string(buf[5 : 5+domainLen])
		targetAddr = targetDomain
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])

	case socksIPv6:
		if n < 22 {
			s.sendReply(clientConn, 0x01) // General failure
			return
		}
		targetAddr = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])

	default:
		s.sendReply(clientConn, 0x08) // Address type not supported
		return
	}

	// If we have a domain name (not IP), resolve it via local DNS proxy
	// This ensures SOCKS connections follow the same DNS rules
	if targetDomain != "" && net.ParseIP(targetAddr) == nil {
		log.Printf("SOCKS: Resolving %s via local DNS proxy", targetDomain)
		ips, err := s.resolveViaLocalDNS(targetDomain)
		if err != nil {
			log.Printf("Failed to resolve %s via local DNS: %v", targetDomain, err)
			s.sendReply(clientConn, 0x04) // Host unreachable
			return
		}
		if len(ips) > 0 {
			// Use the first resolved IP
			targetAddr = ips[0]
			log.Printf("SOCKS: Resolved %s to %s", targetDomain, targetAddr)
		}
	}

	// Format target address (IPv6 addresses need brackets)
	var target string
	if net.ParseIP(targetAddr) != nil && strings.Contains(targetAddr, ":") {
		// IPv6 address needs brackets
		target = fmt.Sprintf("[%s]:%d", targetAddr, port)
	} else {
		target = fmt.Sprintf("%s:%d", targetAddr, port)
	}
	log.Printf("SOCKS CONNECT: %s (original domain: %s)", target, targetDomain)

	// Check if this domain should use a SOCKS proxy
	var upstreamProxy *db.SOCKSProxy
	if targetDomain != "" {
		upstreamProxy = s.findProxyForDomain(targetDomain)
	}

	var targetConn net.Conn
	if upstreamProxy != nil && upstreamProxy.Enabled {
		// Connect through upstream SOCKS proxy
		log.Printf("Routing %s through upstream proxy: %s", target, upstreamProxy.Name)
		targetConn, err = s.connectThroughProxy(target, upstreamProxy)
	} else {
		// Direct connection using resolved IP
		targetConn, err = net.DialTimeout("tcp", target, 10*time.Second)
	}

	if err != nil {
		log.Printf("Failed to connect to %s: %v", target, err)
		s.sendReply(clientConn, 0x05) // Connection refused
		return
	}
	defer targetConn.Close()

	// Send success reply
	s.sendReply(clientConn, 0x00)

	// Remove deadline for data transfer
	clientConn.SetDeadline(time.Time{})

	// Bidirectional copy
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

func (s *SOCKSServer) sendReply(conn net.Conn, status byte) {
	reply := []byte{
		socks5Version,
		status,
		0x00, // Reserved
		socksIPv4,
		0, 0, 0, 0, // Bind address (0.0.0.0)
		0, 0, // Bind port (0)
	}
	conn.Write(reply)
}

func (s *SOCKSServer) findProxyForDomain(domain string) *db.SOCKSProxy {
	// Clean domain
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "www.")

	// Check for exact domain match
	rule, err := db.GetDomainRule(s.db, domain)
	if err == nil && rule != nil && rule.ProxyID > 0 {
		proxy, err := db.GetSOCKSProxy(s.db, rule.ProxyID)
		if err == nil && proxy != nil {
			return proxy
		}
	}

	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		rule, err := db.GetDomainRule(s.db, parentDomain)
		if err == nil && rule != nil && rule.ProxyID > 0 {
			proxy, err := db.GetSOCKSProxy(s.db, rule.ProxyID)
			if err == nil && proxy != nil {
				return proxy
			}
		}
	}

	// Check wildcard
	for i := 0; i < len(parts)-1; i++ {
		wildcardDomain := "*." + strings.Join(parts[i:], ".")
		rule, err := db.GetDomainRule(s.db, wildcardDomain)
		if err == nil && rule != nil && rule.ProxyID > 0 {
			proxy, err := db.GetSOCKSProxy(s.db, rule.ProxyID)
			if err == nil && proxy != nil {
				return proxy
			}
		}
	}

	return nil
}

func (s *SOCKSServer) connectThroughProxy(target string, proxy *db.SOCKSProxy) (net.Conn, error) {
	// Connect to upstream SOCKS proxy
	proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// SOCKS5 greeting
	authMethod := byte(socksNoAuth)
	if proxy.Username != "" {
		authMethod = byte(socksUserPass)
	}

	_, err = conn.Write([]byte{socks5Version, 0x01, authMethod})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send greeting: %w", err)
	}

	// Read auth response
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read auth response: %w", err)
	}

	if buf[1] == socksUserPass {
		// Username/password authentication
		userLen := byte(len(proxy.Username))
		passLen := byte(len(proxy.Password))
		authReq := []byte{0x01, userLen}
		authReq = append(authReq, []byte(proxy.Username)...)
		authReq = append(authReq, passLen)
		authReq = append(authReq, []byte(proxy.Password)...)

		_, err = conn.Write(authReq)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send auth: %w", err)
		}

		_, err = io.ReadFull(conn, buf)
		if err != nil || buf[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("authentication failed")
		}
	}

	// Parse target host and port
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Build CONNECT request
	request := []byte{socks5Version, socksConnect, 0x00}

	// Check if host is IP or domain
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			request = append(request, socksIPv4)
			request = append(request, ip.To4()...)
		} else {
			request = append(request, socksIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		request = append(request, socksDomain)
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}

	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	request = append(request, portBytes...)

	_, err = conn.Write(request)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send connect request: %w", err)
	}

	// Read response
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read connect response: %w", err)
	}

	if n < 2 || response[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("proxy connection failed, status: %d", response[1])
	}

	return conn, nil
}
