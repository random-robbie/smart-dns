package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

type DNSServer struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Primary string `json:"primary"`
	Secondary string `json:"secondary"`
}

type SOCKSProxy struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type DomainRule struct {
	ID       int    `json:"id"`
	Domain   string `json:"domain"`
	ServerID int    `json:"server_id"`
	ProxyID  int    `json:"proxy_id,omitempty"`  // Optional SOCKS proxy
}

func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS dns_servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		primary_server TEXT NOT NULL,
		secondary_server TEXT
	);

	CREATE TABLE IF NOT EXISTS socks_proxies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		username TEXT,
		password TEXT,
		enabled INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS domain_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		server_id INTEGER NOT NULL,
		proxy_id INTEGER,
		FOREIGN KEY(server_id) REFERENCES dns_servers(id) ON DELETE CASCADE,
		FOREIGN KEY(proxy_id) REFERENCES socks_proxies(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_domain ON domain_rules(domain);
	`

	_, err = db.Exec(schema)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func InitializeDefaultServers(db *sql.DB) error {
	// Check if servers already exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM dns_servers").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil // Already initialized
	}

	// Insert default servers
	servers := []struct {
		name      string
		primary   string
		secondary string
	}{
		{"SmartDNSProxy 1", "35.178.60.174", "54.229.171.243"},
		{"SmartDNSProxy 2", "54.229.171.243", "35.178.60.174"},
		{"NordVPN SmartDNS", "103.86.96.103", "103.86.99.103"},
		{"Default (1.1.1.1)", "1.1.1.1", "8.8.8.8"},
		{"Default (8.8.8.8)", "8.8.8.8", "1.1.1.1"},
		{"Router (192.168.1.1)", "192.168.1.1", "1.1.1.1"},
	}

	for _, s := range servers {
		_, err := db.Exec(
			"INSERT INTO dns_servers (name, primary_server, secondary_server) VALUES (?, ?, ?)",
			s.name, s.primary, s.secondary,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// DNS Server CRUD operations
func GetDNSServers(db *sql.DB) ([]DNSServer, error) {
	rows, err := db.Query("SELECT id, name, primary_server, secondary_server FROM dns_servers")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []DNSServer
	for rows.Next() {
		var s DNSServer
		if err := rows.Scan(&s.ID, &s.Name, &s.Primary, &s.Secondary); err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}

	return servers, nil
}

func GetDNSServer(db *sql.DB, id int) (*DNSServer, error) {
	var s DNSServer
	err := db.QueryRow(
		"SELECT id, name, primary_server, secondary_server FROM dns_servers WHERE id = ?",
		id,
	).Scan(&s.ID, &s.Name, &s.Primary, &s.Secondary)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func AddDNSServer(db *sql.DB, name, primary, secondary string) (int64, error) {
	result, err := db.Exec(
		"INSERT INTO dns_servers (name, primary_server, secondary_server) VALUES (?, ?, ?)",
		name, primary, secondary,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func UpdateDNSServer(db *sql.DB, id int, name, primary, secondary string) error {
	_, err := db.Exec(
		"UPDATE dns_servers SET name = ?, primary_server = ?, secondary_server = ? WHERE id = ?",
		name, primary, secondary, id,
	)
	return err
}

func DeleteDNSServer(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM dns_servers WHERE id = ?", id)
	return err
}

// Domain Rule CRUD operations
func GetDomainRules(db *sql.DB) ([]DomainRule, error) {
	rows, err := db.Query("SELECT id, domain, server_id, COALESCE(proxy_id, 0) FROM domain_rules ORDER BY domain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DomainRule
	for rows.Next() {
		var r DomainRule
		if err := rows.Scan(&r.ID, &r.Domain, &r.ServerID, &r.ProxyID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}

	return rules, nil
}

func GetDomainRule(db *sql.DB, domain string) (*DomainRule, error) {
	var r DomainRule
	err := db.QueryRow(
		"SELECT id, domain, server_id, COALESCE(proxy_id, 0) FROM domain_rules WHERE domain = ?",
		domain,
	).Scan(&r.ID, &r.Domain, &r.ServerID, &r.ProxyID)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func AddDomainRule(db *sql.DB, domain string, serverID int) error {
	_, err := db.Exec(
		"INSERT OR REPLACE INTO domain_rules (domain, server_id) VALUES (?, ?)",
		domain, serverID,
	)
	return err
}

func DeleteDomainRule(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM domain_rules WHERE id = ?", id)
	return err
}

func DeleteDomainRuleByDomain(db *sql.DB, domain string) error {
	_, err := db.Exec("DELETE FROM domain_rules WHERE domain = ?", domain)
	return err
}

func BulkAddDomainRules(db *sql.DB, domains []string, serverID int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT OR REPLACE INTO domain_rules (domain, server_id) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		_, err := stmt.Exec(domain, serverID)
		if err != nil {
			return fmt.Errorf("failed to add domain %s: %w", domain, err)
		}
	}

	return tx.Commit()
}

// SOCKS Proxy CRUD operations
func GetSOCKSProxies(db *sql.DB) ([]SOCKSProxy, error) {
	rows, err := db.Query("SELECT id, name, host, port, username, password, enabled FROM socks_proxies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []SOCKSProxy
	for rows.Next() {
		var p SOCKSProxy
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.Username, &p.Password, &enabled); err != nil {
			return nil, err
		}
		p.Enabled = enabled == 1
		proxies = append(proxies, p)
	}

	return proxies, nil
}

func GetSOCKSProxy(db *sql.DB, id int) (*SOCKSProxy, error) {
	var p SOCKSProxy
	var enabled int
	err := db.QueryRow(
		"SELECT id, name, host, port, username, password, enabled FROM socks_proxies WHERE id = ?",
		id,
	).Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.Username, &p.Password, &enabled)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Enabled = enabled == 1

	return &p, nil
}

func AddSOCKSProxy(db *sql.DB, name, host string, port int, username, password string, enabled bool) (int64, error) {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	result, err := db.Exec(
		"INSERT INTO socks_proxies (name, host, port, username, password, enabled) VALUES (?, ?, ?, ?, ?, ?)",
		name, host, port, username, password, enabledInt,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func UpdateSOCKSProxy(db *sql.DB, id int, name, host string, port int, username, password string, enabled bool) error {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := db.Exec(
		"UPDATE socks_proxies SET name = ?, host = ?, port = ?, username = ?, password = ?, enabled = ? WHERE id = ?",
		name, host, port, username, password, enabledInt, id,
	)
	return err
}

func DeleteSOCKSProxy(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM socks_proxies WHERE id = ?", id)
	return err
}

// Update domain rule to optionally include SOCKS proxy
func AddDomainRuleWithProxy(db *sql.DB, domain string, serverID, proxyID int) error {
	var query string
	var args []interface{}

	if proxyID > 0 {
		query = "INSERT OR REPLACE INTO domain_rules (domain, server_id, proxy_id) VALUES (?, ?, ?)"
		args = []interface{}{domain, serverID, proxyID}
	} else {
		query = "INSERT OR REPLACE INTO domain_rules (domain, server_id) VALUES (?, ?)"
		args = []interface{}{domain, serverID}
	}

	_, err := db.Exec(query, args...)
	return err
}
