package cloud

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockCloudTrailClient is a mock implementation of the CloudTrail client
type MockCloudTrailClient struct {
	mock.Mock
}

func (m *MockCloudTrailClient) LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*cloudtrail.LookupEventsOutput), args.Error(1)
}

func TestCloudTrailCollector(t *testing.T) {
	// Create a channel for events
	eventsChan := make(chan []byte, 10)
	defer close(eventsChan)

	// Create mock client
	mockClient := new(MockCloudTrailClient)

	// Create collector with mock client
	collector := &Collector{
		client:     mockClient, // CloudTrailClient interface
		region:     "us-west-2",
		eventsChan: eventsChan,
		stopChan:   make(chan struct{}),
	}

	// Create test event
	testEvent := types.Event{
		EventTime:    aws.Time(time.Now()),
		EventName:    aws.String("TestEvent"),
		EventSource:  aws.String("test.source"),
		CloudTrailEvent: aws.String(`{"eventVersion": "1.0", "eventName": "TestEvent", "eventType": "AwsApiCall", "userIdentity": {"type": "IAMUser", "principalId": "test-user"}, "requestID": "test-request-id"}`),
	}

	// Set up mock expectations
	mockClient.On("LookupEvents", mock.Anything, mock.Anything).Return(&cloudtrail.LookupEventsOutput{
		Events: []types.Event{testEvent},
	}, nil)

	// Start collector
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := collector.Start(ctx)
	assert.NoError(t, err)

	// Wait for event
	select {
	case data := <-eventsChan:
		var event CloudTrailEvent
		err := json.Unmarshal(data, &event)
		assert.NoError(t, err)
		assert.Equal(t, "TestEvent", event.EventName)
		assert.Equal(t, "test.source", event.EventSource)
		assert.Equal(t, "AwsApiCall", event.EventType)
		assert.Equal(t, "test-request-id", event.RequestID)
		assert.Equal(t, "us-west-2", event.Region)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for event")
	}

	// Stop collector
	collector.Stop()
	mockClient.AssertExpectations(t)
}

func TestCloudTrailCollectorError(t *testing.T) {
	// Create a channel for events
	eventsChan := make(chan []byte, 10)
	defer close(eventsChan)

	// Create mock client
	mockClient := new(MockCloudTrailClient)

	// Create collector with mock client
	collector := &Collector{
		client:     mockClient,
		region:     "us-west-2",
		eventsChan: eventsChan,
		stopChan:   make(chan struct{}),
	}

	// Set up mock to return error
	mockClient.On("LookupEvents", mock.Anything, mock.Anything).Return(nil, assert.AnError)

	// Start collector
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := collector.Start(ctx)
	assert.NoError(t, err)

	// Wait for error to be logged
	time.Sleep(100 * time.Millisecond)

	// Stop collector
	collector.Stop()
	mockClient.AssertExpectations(t)
} 