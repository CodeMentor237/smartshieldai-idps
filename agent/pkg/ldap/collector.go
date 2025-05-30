package ldap

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/smartshieldai-idps/agent/internal/models"
)

// Config represents the LDAP collector configuration
type Config struct {
	Server   string
	Port     int
	BaseDN   string
	BindDN   string
	Password string
	UseTLS   bool
	Timeout  time.Duration
}

// Collector represents the LDAP data collector
type Collector struct {
	config Config
	conn   *ldap.Conn
}

// NewCollector creates a new LDAP collector
func NewCollector(config Config) (*Collector, error) {
	// Create LDAP connection
	var conn *ldap.Conn
	var err error

	addr := fmt.Sprintf("%s:%d", config.Server, config.Port)
	if config.UseTLS {
		conn, err = ldap.DialTLS("tcp", addr, &tls.Config{
			InsecureSkipVerify: false,
		})
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %v", err)
	}

	// Set timeout
	conn.SetTimeout(config.Timeout)

	// Bind with credentials
	if err := conn.Bind(config.BindDN, config.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind to LDAP server: %v", err)
	}

	return &Collector{
		config: config,
		conn:   conn,
	}, nil
}

// CollectLoginEvents collects recent login events from Active Directory
func (c *Collector) CollectLoginEvents() ([]models.AgentData, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("LDAP connection is not established")
	}

	// Search for recent login events
	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(objectCategory=person))",
		[]string{"cn", "sAMAccountName", "memberOf", "lastLogon", "whenCreated", "userAccountControl"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	// Convert LDAP entries to AgentData
	var events []models.AgentData
	for _, entry := range result.Entries {
		// Parse last logon time
		lastLogon := time.Unix(0, 0)
		if lastLogonStr := entry.GetAttributeValue("lastLogon"); lastLogonStr != "" {
			if t, err := time.Parse("20060102150405Z", lastLogonStr); err == nil {
				lastLogon = t
			}
		}

		// Get user roles from memberOf attribute
		roles := entry.GetAttributeValues("memberOf")

		// Create event data
		event := models.AgentData{
			Type:      "user_behavior",
			Timestamp: time.Now(),
			Source:    "ldap",
			RawData: map[string]interface{}{
				"username":     entry.GetAttributeValue("sAMAccountName"),
				"display_name": entry.GetAttributeValue("cn"),
				"last_logon":   lastLogon,
				"roles":        roles,
				"created":      entry.GetAttributeValue("whenCreated"),
				"enabled":      (entry.GetAttributeValue("userAccountControl") != "514"), // 514 = disabled account
			},
		}

		events = append(events, event)
	}

	return events, nil
}

// Close closes the LDAP connection
func (c *Collector) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// GetUserRoles retrieves the roles for a specific user
func (c *Collector) GetUserRoles(username string) ([]string, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("LDAP connection is not established")
	}

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username)),
		[]string{"memberOf"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	return result.Entries[0].GetAttributeValues("memberOf"), nil
} 