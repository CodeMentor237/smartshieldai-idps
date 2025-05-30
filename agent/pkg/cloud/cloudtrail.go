package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// CloudTrailEvent represents a normalized CloudTrail event
type CloudTrailEvent struct {
	Timestamp    time.Time       `json:"timestamp"`
	EventName    string         `json:"event_name"`
	EventSource  string         `json:"event_source"`
	EventType    string         `json:"event_type"`
	UserIdentity json.RawMessage `json:"user_identity"`
	RequestID    string         `json:"request_id"`
	EventData    json.RawMessage `json:"event_data"`
	Severity     string         `json:"severity"`
	Region       string         `json:"region"`
}

// CloudTrailClient is an interface for CloudTrail client (for testability)
type CloudTrailClient interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// Collector represents a CloudTrail event collector
type Collector struct {
	client     CloudTrailClient
	region     string
	eventsChan chan<- []byte
	stopChan   chan struct{}
}

// NewCollector creates a new CloudTrail event collector
func NewCollector(region string, eventsChan chan<- []byte) (*Collector, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	// Create CloudTrail client
	client := cloudtrail.NewFromConfig(cfg)

	return &Collector{
		client:     client,
		region:     region,
		eventsChan: eventsChan,
		stopChan:   make(chan struct{}),
	}, nil
}

// Start begins collecting CloudTrail events
func (c *Collector) Start(ctx context.Context) error {
	// Start event collection in a goroutine
	go c.collectEvents(ctx)
	return nil
}

// Stop stops collecting CloudTrail events
func (c *Collector) Stop() {
	close(c.stopChan)
}

// collectEvents continuously collects CloudTrail events
func (c *Collector) collectEvents(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			if err := c.fetchEvents(ctx); err != nil {
				log.Printf("Error fetching CloudTrail events: %v", err)
			}
		}
	}
}

// fetchEvents retrieves recent CloudTrail events
func (c *Collector) fetchEvents(ctx context.Context) error {
	// Get events from the last 5 minutes
	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute)

	input := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(endTime),
	}

	result, err := c.client.LookupEvents(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to lookup events: %v", err)
	}

	// Process each event
	for _, event := range result.Events {
		normalizedEvent, err := c.normalizeEvent(event)
		if err != nil {
			log.Printf("Error normalizing event: %v", err)
			continue
		}

		// Marshal and send event
		data, err := json.Marshal(normalizedEvent)
		if err != nil {
			log.Printf("Error marshaling event: %v", err)
			continue
		}

		select {
		case c.eventsChan <- data:
		default:
			log.Printf("Warning: Events channel is full, dropping event")
		}
	}

	return nil
}

// normalizeEvent converts a CloudTrail event to our normalized format
func (c *Collector) normalizeEvent(event types.Event) (CloudTrailEvent, error) {
	// Parse event time
	eventTime := time.Now()
	if event.EventTime != nil {
		eventTime = *event.EventTime
	}

	// Default values
	eventName := ""
	if event.EventName != nil {
		eventName = *event.EventName
	}
	eventSource := ""
	if event.EventSource != nil {
		eventSource = *event.EventSource
	}

	// Parse CloudTrailEvent JSON for additional fields
	var raw map[string]interface{}
	var userIdentity json.RawMessage
	requestID := ""
	eventType := ""
	severity := "info"
	if event.CloudTrailEvent != nil {
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &raw); err == nil {
			if v, ok := raw["userIdentity"]; ok {
				if b, err := json.Marshal(v); err == nil {
					userIdentity = b
				}
			}
			if v, ok := raw["eventType"].(string); ok {
				eventType = v
			}
			if v, ok := raw["requestID"].(string); ok {
				requestID = v
			}
			if v, ok := raw["errorCode"]; ok && v != nil {
				severity = "error"
			}
			if v, ok := raw["errorMessage"]; ok && v != nil {
				severity = "error"
			}
		}
	}

	// Create normalized event
	normalized := CloudTrailEvent{
		Timestamp:    eventTime,
		EventName:    eventName,
		EventSource:  eventSource,
		EventType:    eventType,
		UserIdentity: userIdentity,
		RequestID:    requestID,
		EventData:    json.RawMessage([]byte("{}")),
		Severity:     severity,
		Region:       c.region,
	}
	if event.CloudTrailEvent != nil {
		normalized.EventData = json.RawMessage(*event.CloudTrailEvent)
	}
	return normalized, nil
} 