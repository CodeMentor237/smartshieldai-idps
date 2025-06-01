package xai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// ModelOutput represents the output from an ML model
type ModelOutput struct {
	Score        float64 `json:"score"`
	Confidence   float64 `json:"confidence"`
	ModelVersion string  `json:"model_version"`
}

// ExplanationRequest represents a request for explanation generation
type ExplanationRequest struct {
	ModelOutput    ModelOutput `json:"model_output"`
	InputFeatures  []float64   `json:"input_features"`
	FeatureNames   []string    `json:"feature_names"`
}

// ExplanationResponse represents the response to an explanation request
type ExplanationResponse struct {
	ID             string                `json:"id"`
	Explanation    *ExplanationData      `json:"explanation"`
}

// RedisClient interface defines the Redis operations we need
type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Keys(ctx context.Context, pattern string) *redis.StringSliceCmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
}

// Handler handles HTTP requests for the XAI service
type Handler struct {
	explainer *Explainer
	cache     RedisClient
}

// NewHandler creates a new XAI handler
func NewHandler(cache RedisClient) *Handler {
	return &Handler{
		explainer: NewExplainer(cache),
		cache:     cache,
	}
}

// RegisterRoutes registers the XAI service routes
func (h *Handler) RegisterRoutes(r *gin.Engine) {
	xai := r.Group("/api/v1/xai")
	{
		xai.POST("/explain", h.handleExplain)
		xai.GET("/explanation/:id", h.handleGetExplanation)
		xai.GET("/explanations", h.handleListExplanations)
	}
}

// handleExplain handles explanation generation requests
func (h *Handler) handleExplain(c *gin.Context) {
	var req ExplanationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate request
	if err := h.validateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate explanation
	explanation, err := h.explainer.GenerateExplanation(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate explanation"})
		return
	}

	// Store explanation with ID for later retrieval
	id := fmt.Sprintf("explanation:%s:%d", explanation.ModelVersion, time.Now().UnixNano())
	if err := h.storeExplanation(c.Request.Context(), id, explanation); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store explanation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          id,
		"explanation": explanation,
	})
}

// handleGetExplanation handles explanation retrieval by ID
func (h *Handler) handleGetExplanation(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing explanation ID"})
		return
	}

	explanation, err := h.getExplanation(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Explanation not found"})
		return
	}

	c.JSON(http.StatusOK, explanation)
}

// handleListExplanations handles listing recent explanations
func (h *Handler) handleListExplanations(c *gin.Context) {
	modelVersion := c.Query("model_version")
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	var start, end time.Time
	var err error

	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid start time format"})
			return
		}
	} else {
		start = time.Now().Add(-24 * time.Hour)
	}

	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid end time format"})
			return
		}
	} else {
		end = time.Now()
	}

	explanations, err := h.listExplanations(c.Request.Context(), modelVersion, start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve explanations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"explanations": explanations})
}

// validateRequest validates the explanation request
func (h *Handler) validateRequest(req ExplanationRequest) error {
	if len(req.InputFeatures) == 0 {
		return fmt.Errorf("input features required")
	}
	if len(req.FeatureNames) != len(req.InputFeatures) {
		return fmt.Errorf("feature names must match input features length")
	}
	if req.ModelOutput.ModelVersion == "" {
		return fmt.Errorf("model version required")
	}
	return nil
}

// storeExplanation stores an explanation in Redis
func (h *Handler) storeExplanation(ctx context.Context, id string, explanation *ExplanationData) error {
	data, err := json.Marshal(explanation)
	if err != nil {
		return err
	}
	return h.cache.Set(ctx, id, data, 7*24*time.Hour).Err()
}

// getExplanation retrieves an explanation from Redis
func (h *Handler) getExplanation(ctx context.Context, id string) (*ExplanationData, error) {
	data, err := h.cache.Get(ctx, id).Bytes()
	if err != nil {
		return nil, err
	}

	var explanation ExplanationData
	if err := json.Unmarshal(data, &explanation); err != nil {
		return nil, err
	}
	return &explanation, nil
}

// listExplanations retrieves recent explanations
func (h *Handler) listExplanations(ctx context.Context, modelVersion string, start, end time.Time) ([]ExplanationData, error) {
	pattern := "explanation:*"
	if modelVersion != "" {
		pattern = fmt.Sprintf("explanation:%s:*", modelVersion)
	}

	var explanations []ExplanationData
	iter := h.cache.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		id := iter.Val()
		explanation, err := h.getExplanation(ctx, id)
		if err != nil {
			continue
		}

		if (explanation.Timestamp.After(start) || explanation.Timestamp.Equal(start)) &&
			(explanation.Timestamp.Before(end) || explanation.Timestamp.Equal(end)) {
			explanations = append(explanations, *explanation)
		}
	}
	
	return explanations, iter.Err()
}
