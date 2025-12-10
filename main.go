package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"smartdns-proxy/internal/api"
	"smartdns-proxy/internal/db"
	"smartdns-proxy/internal/logs"
	"smartdns-proxy/internal/proxy"
	"smartdns-proxy/internal/socks"
)

func main() {
	// Initialize database - use /data for persistence
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/data/smartdns.db"
	}

	// Ensure data directory exists
	os.MkdirAll("/data", 0755)

	database, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Initialize default DNS servers
	if err := db.InitializeDefaultServers(database); err != nil {
		log.Printf("Warning: Failed to initialize default servers: %v", err)
	}

	// Initialize DNS logger (keep last 200 requests)
	dnsLogger := logs.NewDNSLogger(200)

	// Start DNS proxy server
	dnsProxy := proxy.NewDNSProxy(database, "0.0.0.0:53", dnsLogger)
	go func() {
		log.Println("Starting DNS proxy on 0.0.0.0:53 (UDP)")
		if err := dnsProxy.Start(); err != nil {
			log.Fatalf("Failed to start DNS proxy: %v", err)
		}
	}()

	// Start SOCKS5 proxy server
	socksServer := socks.NewSOCKSServer(database, "0.0.0.0:1080")
	go func() {
		log.Println("Starting SOCKS5 proxy on 0.0.0.0:1080")
		if err := socksServer.Start(); err != nil {
			log.Fatalf("Failed to start SOCKS proxy: %v", err)
		}
	}()

	// Start API server
	apiServer := api.NewAPIServer(database, ":8080", dnsLogger)
	go func() {
		log.Println("Starting API server on :8080")
		if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start API server: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	socksServer.Stop()
}
