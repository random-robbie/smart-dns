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

type DomainRule struct {
	ID       int    `json:"id"`
	Domain   string `json:"domain"`
	ServerID int    `json:"server_id"`
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

	CREATE TABLE IF NOT EXISTS domain_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		server_id INTEGER NOT NULL,
		FOREIGN KEY(server_id) REFERENCES dns_servers(id) ON DELETE CASCADE
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
	rows, err := db.Query("SELECT id, domain, server_id FROM domain_rules ORDER BY domain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DomainRule
	for rows.Next() {
		var r DomainRule
		if err := rows.Scan(&r.ID, &r.Domain, &r.ServerID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}

	return rules, nil
}

func GetDomainRule(db *sql.DB, domain string) (*DomainRule, error) {
	var r DomainRule
	err := db.QueryRow(
		"SELECT id, domain, server_id FROM domain_rules WHERE domain = ?",
		domain,
	).Scan(&r.ID, &r.Domain, &r.ServerID)

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
