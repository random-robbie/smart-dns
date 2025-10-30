package logs

import (
	"sync"
	"time"
)

type DNSLogEntry struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
	QueryType string    `json:"query_type"`
	ServerUsed string   `json:"server_used"`
	IsProxied bool      `json:"is_proxied"`
	ResponseTime int64  `json:"response_time_ms"`
	ClientIP string     `json:"client_ip"`
	ClientHost string   `json:"client_host"`
}

type DNSLogger struct {
	logs     []DNSLogEntry
	maxLogs  int
	mu       sync.RWMutex
	counter  int
}

func NewDNSLogger(maxLogs int) *DNSLogger {
	return &DNSLogger{
		logs:    make([]DNSLogEntry, 0, maxLogs),
		maxLogs: maxLogs,
		counter: 0,
	}
}

func (l *DNSLogger) Log(domain, queryType, serverUsed string, isProxied bool, responseTime int64, clientIP, clientHost string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.counter++

	entry := DNSLogEntry{
		ID:           l.counter,
		Timestamp:    time.Now(),
		Domain:       domain,
		QueryType:    queryType,
		ServerUsed:   serverUsed,
		IsProxied:    isProxied,
		ResponseTime: responseTime,
		ClientIP:     clientIP,
		ClientHost:   clientHost,
	}

	// Add to beginning of slice (most recent first)
	l.logs = append([]DNSLogEntry{entry}, l.logs...)

	// Keep only maxLogs entries
	if len(l.logs) > l.maxLogs {
		l.logs = l.logs[:l.maxLogs]
	}
}

func (l *DNSLogger) GetLogs(limit int) []DNSLogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if limit <= 0 || limit > len(l.logs) {
		limit = len(l.logs)
	}

	// Return a copy to avoid race conditions
	result := make([]DNSLogEntry, limit)
	copy(result, l.logs[:limit])
	return result
}

func (l *DNSLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logs = make([]DNSLogEntry, 0, l.maxLogs)
}

func (l *DNSLogger) GetUniqueUnproxiedDomains(limit int) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	seen := make(map[string]bool)
	var domains []string

	for _, entry := range l.logs {
		if !entry.IsProxied && !seen[entry.Domain] {
			seen[entry.Domain] = true
			domains = append(domains, entry.Domain)
			if len(domains) >= limit {
				break
			}
		}
	}

	return domains
}
