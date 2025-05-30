package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	osquery "github.com/osquery/osquery-go"
)

// OsqueryClient wraps the osquery extension client
type OsqueryClient struct {
	client *osquery.ExtensionManagerClient
}

// NewOsqueryClient connects to the local osqueryd socket
func NewOsqueryClient(socketPath string) (*OsqueryClient, error) {
	client, err := osquery.NewClient(socketPath, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to osqueryd: %w", err)
	}
	return &OsqueryClient{client: client}, nil
}

// Query runs an osquery SQL query and returns the results as JSON
func (o *OsqueryClient) Query(query string) ([]byte, error) {
	resp, err := o.client.Query(query)
	if err != nil {
		return nil, fmt.Errorf("osquery query failed: %w", err)
	}
	if resp.Status.Code != 0 {
		return nil, fmt.Errorf("osquery error: %s", resp.Status.Message)
	}
	return json.Marshal(resp.Response)
}

// ScheduleQueries runs osquery queries every 30 seconds and sends results to the backend
func (o *OsqueryClient) ScheduleQueries(ctx context.Context, dataChan chan<- []byte) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			query := "SELECT pid, name, path, cmdline FROM processes LIMIT 5;"
			results, err := o.Query(query)
			if err != nil {
				log.Printf("osquery query error: %v", err)
				continue
			}
			// Send results to data channel
			select {
			case dataChan <- results:
			default:
				log.Printf("Osquery data channel full, dropping results.")
			}
		}
	}
}

// Example usage: run a query and print results
func ExampleOsqueryUsage() {
	client, err := NewOsqueryClient("/var/osquery/osquery.em")
	if err != nil {
		log.Printf("osquery connection error: %v", err)
		return
	}
	defer client.client.Close()

	query := "SELECT pid, name, path, cmdline FROM processes LIMIT 5;"
	results, err := client.Query(query)
	if err != nil {
		log.Printf("osquery query error: %v", err)
		return
	}
	log.Printf("osquery results: %s", string(results))
} 