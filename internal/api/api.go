package api

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"smartdns-proxy/internal/db"
	"smartdns-proxy/internal/logs"
)

type APIServer struct {
	db     *sql.DB
	router *mux.Router
	addr   string
	logger *logs.DNSLogger
}

func NewAPIServer(database *sql.DB, addr string, logger *logs.DNSLogger) *APIServer {
	s := &APIServer{
		db:     database,
		router: mux.NewRouter(),
		addr:   addr,
		logger: logger,
	}

	s.setupRoutes()
	return s
}

func (s *APIServer) setupRoutes() {
	// Serve static files
	s.router.HandleFunc("/", s.serveIndex).Methods("GET")
	s.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	// API routes
	api := s.router.PathPrefix("/api").Subrouter()

	// DNS Servers
	api.HandleFunc("/servers", s.getDNSServers).Methods("GET")
	api.HandleFunc("/servers", s.addDNSServer).Methods("POST")
	api.HandleFunc("/servers/{id}", s.updateDNSServer).Methods("PUT")
	api.HandleFunc("/servers/{id}", s.deleteDNSServer).Methods("DELETE")

	// Domain Rules
	api.HandleFunc("/rules", s.getDomainRules).Methods("GET")
	api.HandleFunc("/rules", s.addDomainRule).Methods("POST")
	api.HandleFunc("/rules/bulk", s.bulkAddDomainRules).Methods("POST")
	api.HandleFunc("/rules/bulk-delete", s.bulkDeleteDomainRules).Methods("POST")
	api.HandleFunc("/rules/{id}", s.deleteDomainRule).Methods("DELETE")

	// DNS Logs
	api.HandleFunc("/logs", s.getDNSLogs).Methods("GET")
	api.HandleFunc("/logs/clear", s.clearDNSLogs).Methods("POST")
	api.HandleFunc("/logs/unproxied", s.getUnproxiedDomains).Methods("GET")

	// Import/Export
	api.HandleFunc("/export", s.exportSettings).Methods("GET")
	api.HandleFunc("/import", s.importSettings).Methods("POST")

	// System Info
	api.HandleFunc("/system/ip", s.getLocalIP).Methods("GET")
	api.HandleFunc("/system/hostname", s.getHostname).Methods("GET")

	// TLS Certificates
	api.HandleFunc("/system/cert", s.exportCertificate).Methods("GET")
	api.HandleFunc("/system/cert/status", s.getCertificateStatus).Methods("GET")

	// Tools
	api.HandleFunc("/tools/discover", s.discoverDomains).Methods("POST")

	// Enable CORS
	s.router.Use(corsMiddleware)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Disable caching
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) Start() error {
	log.Printf("API Server listening on %s", s.addr)
	return http.ListenAndServe(s.addr, s.router)
}

func (s *APIServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/index.html")
}

// DNS Server handlers
func (s *APIServer) getDNSServers(w http.ResponseWriter, r *http.Request) {
	servers, err := db.GetDNSServers(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

func (s *APIServer) addDNSServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Primary   string `json:"primary"`
		Secondary string `json:"secondary"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.Name == "" {
		http.Error(w, "Server name cannot be empty", http.StatusBadRequest)
		return
	}
	if req.Primary == "" {
		http.Error(w, "Primary DNS server cannot be empty", http.StatusBadRequest)
		return
	}

	id, err := db.AddDNSServer(s.db, req.Name, req.Primary, req.Secondary)
	if err != nil {
		// Check for unique constraint violation
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			http.Error(w, "A DNS server with this name already exists", http.StatusConflict)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"id": id})
}

func (s *APIServer) updateDNSServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Name      string `json:"name"`
		Primary   string `json:"primary"`
		Secondary string `json:"secondary"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.Name == "" {
		http.Error(w, "Server name cannot be empty", http.StatusBadRequest)
		return
	}
	if req.Primary == "" {
		http.Error(w, "Primary DNS server cannot be empty", http.StatusBadRequest)
		return
	}

	// Verify server exists
	server, err := db.GetDNSServer(s.db, id)
	if err != nil || server == nil {
		http.Error(w, "DNS server not found", http.StatusNotFound)
		return
	}

	if err := db.UpdateDNSServer(s.db, id, req.Name, req.Primary, req.Secondary); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			http.Error(w, "A DNS server with this name already exists", http.StatusConflict)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *APIServer) deleteDNSServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := db.DeleteDNSServer(s.db, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Domain Rule handlers
func (s *APIServer) getDomainRules(w http.ResponseWriter, r *http.Request) {
	rules, err := db.GetDomainRules(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enrich rules with server information
	type EnrichedRule struct {
		ID         int    `json:"id"`
		Domain     string `json:"domain"`
		ServerID   int    `json:"server_id"`
		ServerName string `json:"server_name"`
	}

	enriched := make([]EnrichedRule, 0, len(rules))
	for _, rule := range rules {
		server, err := db.GetDNSServer(s.db, rule.ServerID)
		if err != nil || server == nil {
			continue
		}

		enriched = append(enriched, EnrichedRule{
			ID:         rule.ID,
			Domain:     rule.Domain,
			ServerID:   rule.ServerID,
			ServerName: server.Name,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enriched)
}

func (s *APIServer) addDomainRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		ServerID int    `json:"server_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.Domain == "" {
		http.Error(w, "Domain cannot be empty", http.StatusBadRequest)
		return
	}
	if req.ServerID <= 0 {
		http.Error(w, "Invalid server ID", http.StatusBadRequest)
		return
	}

	// Validate server exists
	server, err := db.GetDNSServer(s.db, req.ServerID)
	if err != nil || server == nil {
		http.Error(w, "DNS server not found", http.StatusBadRequest)
		return
	}

	// Check for exact duplicates only (allow adding if it updates the rule)
	existingRule, err := db.GetDomainRule(s.db, req.Domain)
	if err == nil && existingRule != nil && existingRule.ServerID == req.ServerID {
		http.Error(w, "Domain rule already exists with same server", http.StatusConflict)
		return
	}

	if err := db.AddDomainRule(s.db, req.Domain, req.ServerID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// validateDomainNotDuplicate checks if domain already exists or is covered by existing rules
func (s *APIServer) validateDomainNotDuplicate(domain string) error {
	// Check if exact domain already exists
	existingRule, err := db.GetDomainRule(s.db, domain)
	if err == nil && existingRule != nil {
		return fmt.Errorf("Domain rule already exists")
	}

	// Check if domain is covered by existing wildcard or parent domain
	covered, coveringDomain := s.isDomainCovered(domain)
	if covered {
		return fmt.Errorf("Domain already covered by rule: %s", coveringDomain)
	}

	return nil
}

// isDomainCovered checks if a domain is already covered by existing rules
func (s *APIServer) isDomainCovered(domain string) (bool, string) {
	// Check parent domains (e.g., video.example.com covered by example.com)
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		parentDomain := strings.Join(parts[i+1:], ".")
		if rule, err := db.GetDomainRule(s.db, parentDomain); err == nil && rule != nil {
			return true, parentDomain
		}
	}

	// Check if covered by wildcard (e.g., sub.example.com covered by *.example.com)
	// Don't check wildcards for single-label or TLD-only patterns (*.com, *.co.uk, etc.)
	for i := 0; i < len(parts)-1; i++ {
		wildcardDomain := "*." + strings.Join(parts[i:], ".")
		if rule, err := db.GetDomainRule(s.db, wildcardDomain); err == nil && rule != nil {
			return true, wildcardDomain
		}
	}

	return false, ""
}

func (s *APIServer) bulkAddDomainRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains  string `json:"domains"`
		ServerID int    `json:"server_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate server ID
	if req.ServerID <= 0 {
		http.Error(w, "Invalid server ID", http.StatusBadRequest)
		return
	}

	// Validate server exists
	server, err := db.GetDNSServer(s.db, req.ServerID)
	if err != nil || server == nil {
		http.Error(w, "DNS server not found", http.StatusBadRequest)
		return
	}

	// Parse domains (support newline, comma, or space separated)
	domains := parseMultipleDomains(req.Domains)

	if len(domains) == 0 {
		http.Error(w, "No valid domains provided", http.StatusBadRequest)
		return
	}

	// Validate each domain and collect valid ones
	var validDomains []string
	var skipped []string
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		// Check for duplicates
		if err := s.validateDomainNotDuplicate(domain); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", domain, err.Error()))
			continue
		}
		validDomains = append(validDomains, domain)
	}

	if len(validDomains) == 0 {
		http.Error(w, fmt.Sprintf("No domains added. Skipped: %s", strings.Join(skipped, ", ")), http.StatusConflict)
		return
	}

	// Add valid domains
	if err := db.BulkAddDomainRules(s.db, validDomains, req.ServerID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to add domains: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"added":   len(validDomains),
		"skipped": len(skipped),
	}
	if len(skipped) > 0 {
		response["skipped_details"] = skipped
	}
	json.NewEncoder(w).Encode(response)
}

func parseMultipleDomains(input string) []string {
	// Replace commas and semicolons with newlines
	input = strings.ReplaceAll(input, ",", "\n")
	input = strings.ReplaceAll(input, ";", "\n")

	lines := strings.Split(input, "\n")
	var domains []string

	for _, line := range lines {
		// Trim whitespace and split by spaces
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				// Remove protocol if present
				part = strings.TrimPrefix(part, "http://")
				part = strings.TrimPrefix(part, "https://")
				// Remove trailing slash
				part = strings.TrimSuffix(part, "/")
				if part != "" {
					domains = append(domains, part)
				}
			}
		}
	}

	return domains
}

func (s *APIServer) deleteDomainRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := db.DeleteDomainRule(s.db, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) bulkDeleteDomainRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int `json:"ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.IDs) == 0 {
		http.Error(w, "No rule IDs provided", http.StatusBadRequest)
		return
	}

	// Delete each rule
	deletedCount := 0
	var errors []string

	for _, id := range req.IDs {
		if err := db.DeleteDomainRule(s.db, id); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to delete rule %d: %v", id, err))
		} else {
			deletedCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"deleted": deletedCount,
		"total":   len(req.IDs),
	}
	if len(errors) > 0 {
		response["errors"] = errors
	}
	json.NewEncoder(w).Encode(response)
}

// DNS Log handlers
func (s *APIServer) getDNSLogs(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 200 // default

	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	logs := s.logger.GetLogs(limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *APIServer) clearDNSLogs(w http.ResponseWriter, r *http.Request) {
	s.logger.Clear()
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) getUnproxiedDomains(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50 // default

	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	domains := s.logger.GetUniqueUnproxiedDomains(limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

// Import/Export handlers
func (s *APIServer) exportSettings(w http.ResponseWriter, r *http.Request) {
	servers, err := db.GetDNSServers(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rules, err := db.GetDomainRules(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	export := struct {
		Version string           `json:"version"`
		Servers []db.DNSServer   `json:"servers"`
		Rules   []db.DomainRule  `json:"rules"`
	}{
		Version: "1.0",
		Servers: servers,
		Rules:   rules,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=smartdns-config.json")
	json.NewEncoder(w).Encode(export)
}

func (s *APIServer) importSettings(w http.ResponseWriter, r *http.Request) {
	var importData struct {
		Version string           `json:"version"`
		Servers []db.DNSServer   `json:"servers"`
		Rules   []db.DomainRule  `json:"rules"`
	}

	if err := json.NewDecoder(r.Body).Decode(&importData); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Create a map to track old server IDs to new server IDs
	serverIDMap := make(map[int]int)

	// Import servers
	for _, server := range importData.Servers {
		id, err := db.AddDNSServer(s.db, server.Name, server.Primary, server.Secondary)
		if err != nil {
			// If server already exists, try to find it
			existingServers, _ := db.GetDNSServers(s.db)
			for _, existing := range existingServers {
				if existing.Name == server.Name && existing.Primary == server.Primary {
					serverIDMap[server.ID] = existing.ID
					break
				}
			}
		} else {
			serverIDMap[server.ID] = int(id)
		}
	}

	// Import rules with mapped server IDs
	importedCount := 0
	for _, rule := range importData.Rules {
		newServerID, ok := serverIDMap[rule.ServerID]
		if !ok {
			continue // Skip rules for servers that weren't imported
		}

		err := db.AddDomainRule(s.db, rule.Domain, newServerID)
		if err == nil {
			importedCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"servers_imported": len(serverIDMap),
		"rules_imported":   importedCount,
	})
}

// System Info handlers
func (s *APIServer) getLocalIP(w http.ResponseWriter, r *http.Request) {
	localIP := getOutboundIP()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"local_ip": localIP,
	})
}

func (s *APIServer) getHostname(w http.ResponseWriter, r *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "smartdns"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hostname":     hostname,
		"hostname_lan": hostname + ".lan",
	})
}

// getOutboundIP gets the preferred outbound IP of this machine
func getOutboundIP() string {
	// Try to connect to a public DNS server to determine local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		// Fallback: try to get any non-loopback IP
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return "127.0.0.1"
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// Certificate handlers
func (s *APIServer) getCertificateStatus(w http.ResponseWriter, r *http.Request) {
	certPath := os.Getenv("TLS_CERT_PATH")
	if certPath == "" {
		certPath = "/data/certs/dns.crt"
	}

	keyPath := os.Getenv("TLS_KEY_PATH")
	if keyPath == "" {
		keyPath = "/data/certs/dns.key"
	}

	certExists := false
	keyExists := false

	if _, err := os.Stat(certPath); err == nil {
		certExists = true
	}
	if _, err := os.Stat(keyPath); err == nil {
		keyExists = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cert_exists": certExists,
		"key_exists":  keyExists,
		"enabled":     certExists && keyExists,
		"cert_path":   certPath,
	})
}

func (s *APIServer) exportCertificate(w http.ResponseWriter, r *http.Request) {
	certPath := os.Getenv("TLS_CERT_PATH")
	if certPath == "" {
		certPath = "/data/certs/dns.crt"
	}

	// Check if certificate exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		http.Error(w, "Certificate not found. Generate certificates first.", http.StatusNotFound)
		return
	}

	// Read certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		http.Error(w, "Failed to read certificate file", http.StatusInternalServerError)
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=smartdns.crt")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(certData)))

	// Write certificate data
	w.Write(certData)
}

// Tools handlers
func (s *APIServer) discoverDomains(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string `json:"url"`
		ServerID int    `json:"server_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Fetch the page with custom transport to handle SSL and redirects
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip SSL verification for discovery
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(req.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch URL: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusInternalServerError)
		return
	}

	// Extract domains from HTML
	domains := extractDomainsFromHTML(string(body), req.URL)

	// Test each domain
	results := make([]map[string]interface{}, 0)
	tested := make(map[string]bool)

	for _, domain := range domains {
		if tested[domain] {
			continue
		}
		tested[domain] = true

		// Test with SmartDNS
		smartIPs := resolveDomain(domain, s.db, req.ServerID)

		// Test with default DNS
		defaultIPs := resolveDomainDefault(domain)

		// Check if IPs differ
		differs := !stringSlicesEqual(smartIPs, defaultIPs)

		results = append(results, map[string]interface{}{
			"domain":      domain,
			"smart_ips":   smartIPs,
			"default_ips": defaultIPs,
			"differs":     differs,
			"recommended": differs || strings.Contains(domain, extractBaseDomain(req.URL)),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":     req.URL,
		"domains": results,
	})
}

func shouldIgnoreDomain(domain string) bool {
	// List of domains to ignore (social media, tracking, analytics, etc.)
	ignoredDomains := []string{
		"x.com",
		"twitter.com",
		"facebook.com",
		"tiktok.com",
		"youtube.com",
		"w3.org",
		"cookielaw.org",
		"schema.org",
		"googleapis.com",
		"gstatic.com",
		"google-analytics.com",
		"googletagmanager.com",
		"doubleclick.net",
		"facebook.net",
		"linkedin.com",
		"instagram.com",
	}

	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "www.")

	for _, ignored := range ignoredDomains {
		if domain == ignored || strings.HasSuffix(domain, "."+ignored) {
			return true
		}
	}

	return false
}

func extractDomainsFromHTML(html string, baseURL string) []string {
	domains := make(map[string]bool)

	// Extract base domain from URL
	baseDomain := extractBaseDomain(baseURL)
	if baseDomain != "" {
		domains[baseDomain] = true
	}

	// Regular expressions to find domains in HTML
	patterns := []string{
		`(?:src|href|data-src|poster)=["']https?://([^/"']+)`,
		`url\(["']?https?://([^/"')]+)`,
		`//([a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,})`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				domain := strings.ToLower(match[1])
				// Clean up domain
				domain = strings.TrimPrefix(domain, "www.")
				if isValidDomain(domain) && !shouldIgnoreDomain(domain) {
					domains[domain] = true
					// Also add www variant
					domains["www."+domain] = true
				}
			}
		}
	}

	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}

func extractBaseDomain(urlStr string) string {
	// Parse URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	host := strings.ToLower(u.Host)
	host = strings.TrimPrefix(host, "www.")

	// Remove port if present
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	return host
}

func isValidDomain(domain string) bool {
	// Basic validation
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Must not start or end with dot or hyphen
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}

	// Check for valid characters
	validDomain := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return validDomain.MatchString(domain)
}

func resolveDomain(domain string, database *sql.DB, serverID int) []string {
	// Get DNS server
	server, err := db.GetDNSServer(database, serverID)
	if err != nil || server == nil {
		return []string{}
	}

	// Use the DNS server to resolve
	dnsServer := server.Primary + ":53"

	ips, err := net.LookupHost(domain)
	if err != nil {
		// Try using specific DNS server
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, dnsServer)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ips, err = resolver.LookupHost(ctx, domain)
		if err != nil {
			return []string{}
		}
	}

	return ips
}

func resolveDomainDefault(domain string) []string {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return []string{}
	}
	return ips
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]bool)
	for _, v := range a {
		aMap[v] = true
	}

	for _, v := range b {
		if !aMap[v] {
			return false
		}
	}

	return true
}
