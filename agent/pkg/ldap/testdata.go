package ldap

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// UserBehavior represents a user's behavior event
type UserBehavior struct {
	Timestamp   time.Time `json:"timestamp"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	IPAddress   string    `json:"ip_address"`
	Success     bool      `json:"success"`
	FailureCode string    `json:"failure_code,omitempty"`
}

// TestDataGenerator generates test datasets for user behavior
type TestDataGenerator struct {
	users     []string
	roles     []string
	actions   []string
	resources []string
	ips       []string
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator() *TestDataGenerator {
	return &TestDataGenerator{
		users: []string{
			"john.doe", "jane.smith", "admin.user", "guest.user",
			"power.user", "service.account", "system.user",
		},
		roles: []string{
			"administrator", "power_user", "user", "guest",
		},
		actions: []string{
			"login", "logout", "read", "write", "delete",
			"create", "modify", "execute", "access",
		},
		resources: []string{
			"/etc/passwd", "/var/log/auth.log", "/home/user",
			"/opt/application", "/var/www/html", "/root",
			"/etc/shadow", "/var/log/syslog",
		},
		ips: []string{
			"192.168.1.100", "10.0.0.50", "172.16.0.25",
			"192.168.1.101", "10.0.0.51", "172.16.0.26",
		},
	}
}

// GenerateDataset generates a test dataset with specified parameters
func (g *TestDataGenerator) GenerateDataset(
	numEvents int,
	startTime time.Time,
	endTime time.Time,
	outputPath string,
) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Generate events
	events := make([]UserBehavior, 0, numEvents)
	timeRange := endTime.Sub(startTime).Seconds()

	for i := 0; i < numEvents; i++ {
		// Generate random timestamp within range
		seconds := rand.Float64() * timeRange
		timestamp := startTime.Add(time.Duration(seconds) * time.Second)

		// Generate random event
		event := UserBehavior{
			Timestamp: timestamp,
			Username:  g.users[rand.Intn(len(g.users))],
			Role:      g.roles[rand.Intn(len(g.roles))],
			Action:    g.actions[rand.Intn(len(g.actions))],
			Resource:  g.resources[rand.Intn(len(g.resources))],
			IPAddress: g.ips[rand.Intn(len(g.ips))],
			Success:   rand.Float32() > 0.1, // 90% success rate
		}

		// Add failure code for failed events
		if !event.Success {
			event.FailureCode = fmt.Sprintf("ERR_%d", rand.Intn(5)+1)
		}

		events = append(events, event)
	}

	// Write to file
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal events: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write events: %v", err)
	}

	return nil
}

// GenerateAnomalyDataset generates a test dataset with injected anomalies
func (g *TestDataGenerator) GenerateAnomalyDataset(
	numEvents int,
	startTime time.Time,
	endTime time.Time,
	outputPath string,
	anomalyRate float64,
) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Generate events
	events := make([]UserBehavior, 0, numEvents)
	timeRange := endTime.Sub(startTime).Seconds()

	for i := 0; i < numEvents; i++ {
		// Generate random timestamp within range
		seconds := rand.Float64() * timeRange
		timestamp := startTime.Add(time.Duration(seconds) * time.Second)

		// Determine if this is an anomaly
		isAnomaly := rand.Float32() < float32(anomalyRate)

		// Generate event
		event := UserBehavior{
			Timestamp: timestamp,
			Username:  g.users[rand.Intn(len(g.users))],
			Role:      g.roles[rand.Intn(len(g.roles))],
			Action:    g.actions[rand.Intn(len(g.actions))],
			Resource:  g.resources[rand.Intn(len(g.resources))],
			IPAddress: g.ips[rand.Intn(len(g.ips))],
			Success:   rand.Float32() > 0.1,
		}

		// Inject anomalies
		if isAnomaly {
			// Randomly choose anomaly type
			switch rand.Intn(5) {
			case 0: // Unusual time
				event.Timestamp = event.Timestamp.Add(24 * time.Hour)
			case 1: // Unusual IP
				event.IPAddress = "192.168.1.200"
			case 2: // Unusual resource access
				event.Resource = "/etc/shadow"
				event.Role = "guest"
			case 3: // Multiple rapid actions
				event.Timestamp = event.Timestamp.Add(time.Duration(rand.Intn(5)) * time.Second)
			case 4: // Failed privileged action
				event.Action = "modify"
				event.Resource = "/etc/passwd"
				event.Success = false
				event.FailureCode = "ERR_PERMISSION_DENIED"
			}
		}

		// Add failure code for failed events
		if !event.Success && event.FailureCode == "" {
			event.FailureCode = fmt.Sprintf("ERR_%d", rand.Intn(5)+1)
		}

		events = append(events, event)
	}

	// Write to file
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal events: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write events: %v", err)
	}

	return nil
} 