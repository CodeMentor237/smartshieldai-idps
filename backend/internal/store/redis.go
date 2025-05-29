package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/smartshieldai-idps/backend/internal/models"
)

const (
	dataKeyPrefix = "agent:data:"
	dataExpiry    = 24 * time.Hour // Keep data for 24 hours
)

// Store represents a Redis-backed data store
type Store struct {
	client *redis.Client
}

// NewStore creates a new Redis store
func NewStore(redisURL string) (*Store, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing Redis URL: %v", err)
	}

	client := redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("error connecting to Redis: %v", err)
	}

	return &Store{client: client}, nil
}

// StoreData stores agent data in Redis
func (s *Store) StoreData(ctx context.Context, data *models.AgentData) error {
	// Generate key with timestamp for time-based querying
	key := fmt.Sprintf("%s%s:%d", dataKeyPrefix, data.DataType, data.Timestamp.UnixNano())
	
	// Store data as JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %v", err)
	}

	// Store with expiration
	if err := s.client.Set(ctx, key, jsonData, dataExpiry).Err(); err != nil {
		return fmt.Errorf("error storing data: %v", err)
	}

	return nil
}

// GetRecentData retrieves recent data from Redis
func (s *Store) GetRecentData(ctx context.Context, dataType string, since time.Duration) ([]*models.AgentData, error) {
	// Get all keys for the data type within the time range
	pattern := fmt.Sprintf("%s%s:*", dataKeyPrefix, dataType)
	minTime := time.Now().Add(-since).UnixNano()
	
	var cursor uint64
	var result []*models.AgentData

	for {
		var batch []string
		var err error
		batch, cursor, err = s.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("error scanning keys: %v", err)
		}

		// Filter keys by timestamp and fetch data
		for _, key := range batch {
			// Extract timestamp from key
			var timestamp int64
			if _, err := fmt.Sscanf(key, dataKeyPrefix+"%s:%d", &dataType, &timestamp); err != nil {
				continue
			}

			if timestamp < minTime {
				continue
			}

			// Get data
			jsonData, err := s.client.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}

			var data models.AgentData
			if err := json.Unmarshal(jsonData, &data); err != nil {
				continue
			}

			result = append(result, &data)
		}

		if cursor == 0 {
			break
		}
	}

	return result, nil
}

// Close closes the Redis connection
func (s *Store) Close() error {
	return s.client.Close()
}