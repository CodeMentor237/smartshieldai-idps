package xai

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sort"
	"time"
)

// FeatureImportance represents the importance score of a feature
type FeatureImportance struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// ExplanationData represents the full explanation with feature importance
type ExplanationData struct {
	ModelOutput       ModelOutput          `json:"model_output"`
	Features         []float64            `json:"features"`
	FeatureNames     []string            `json:"feature_names"`
	Explanation      string              `json:"explanation"`
	FeatureImportance []FeatureImportance `json:"feature_importance"`
	ConfidenceScore  float64             `json:"confidence_score"`
	ModelVersion     string              `json:"model_version"`
	Timestamp        time.Time           `json:"timestamp"`
}

// Explainer handles explanation generation for ML model outputs
type Explainer struct {
	cache RedisClient
}

// NewExplainer creates a new explainer instance
func NewExplainer(cache RedisClient) *Explainer {
	return &Explainer{
		cache: cache,
	}
}

// GenerateExplanation generates an explanation for a given model output
func (e *Explainer) GenerateExplanation(ctx context.Context, req ExplanationRequest) (*ExplanationData, error) {
	// Try to get cached explanation
	cacheKey := fmt.Sprintf("xai:explanation:%s:%v", req.ModelOutput.ModelVersion, req.InputFeatures)
	if cached, err := e.getFromCache(ctx, cacheKey); err == nil {
		return cached, nil
	}

	// Calculate feature importance scores
	importance := e.calculateFeatureImportance(req.InputFeatures, req.FeatureNames, req.ModelOutput)

	// Generate natural language explanation
	explanation := e.generateNaturalLanguageExplanation(importance, req.ModelOutput)

	// Create explanation data
	data := &ExplanationData{
		ModelOutput:       req.ModelOutput,
		Features:         req.InputFeatures,
		FeatureNames:     req.FeatureNames,
		Explanation:      explanation,
		FeatureImportance: importance,
		ConfidenceScore:  req.ModelOutput.Confidence,
		ModelVersion:     req.ModelOutput.ModelVersion,
		Timestamp:        time.Now(),
	}

	// Cache the explanation
	if err := e.cacheExplanation(ctx, cacheKey, data); err != nil {
		log.Printf("Warning: failed to cache explanation: %v", err)
	}

	return data, nil
}

// calculateFeatureImportance calculates SHAP-like importance scores
func (e *Explainer) calculateFeatureImportance(features []float64, names []string, output ModelOutput) []FeatureImportance {
	importance := make([]FeatureImportance, len(features))
	
	// Calculate normalized feature contributions
	sum := 0.0
	for i, val := range features {
		// Calculate feature contribution based on value and model confidence
		contribution := math.Abs(val) * output.Confidence
		sum += contribution
		
		importance[i] = FeatureImportance{
			Name:  names[i],
			Score: contribution,
		}
	}

	// Normalize scores
	if sum > 0 {
		for i := range importance {
			importance[i].Score /= sum
		}
	}

	// Sort by importance score
	sort.Slice(importance, func(i, j int) bool {
		return importance[i].Score > importance[j].Score
	})

	return importance
}

// generateNaturalLanguageExplanation creates a human-readable explanation
func (e *Explainer) generateNaturalLanguageExplanation(importance []FeatureImportance, output ModelOutput) string {
	// Get top contributing features
	var topFeatures []FeatureImportance
	if len(importance) > 3 {
		topFeatures = importance[:3]
	} else {
		topFeatures = importance
	}

	// Generate explanation based on confidence and top features
	var explanation string
	if output.Confidence > 0.9 {
		explanation = "High confidence detection"
	} else if output.Confidence > 0.7 {
		explanation = "Moderate confidence detection"
	} else {
		explanation = "Low confidence detection"
	}

	explanation += fmt.Sprintf(" (%.1f%% confidence). ", output.Confidence*100)
	explanation += "Key factors: "

	for i, feat := range topFeatures {
		if i > 0 {
			explanation += ", "
		}
		explanation += fmt.Sprintf("%s (%.1f%% contribution)", feat.Name, feat.Score*100)
	}

	return explanation
}

// getFromCache attempts to retrieve a cached explanation
func (e *Explainer) getFromCache(ctx context.Context, key string) (*ExplanationData, error) {
	if e.cache == nil {
		return nil, fmt.Errorf("cache not initialized")
	}

	data, err := e.cache.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}

	var explanation ExplanationData
	if err := json.Unmarshal(data, &explanation); err != nil {
		return nil, err
	}

	return &explanation, nil
}

// cacheExplanation stores an explanation in Redis
func (e *Explainer) cacheExplanation(ctx context.Context, key string, data *ExplanationData) error {
	if e.cache == nil {
		return fmt.Errorf("cache not initialized")
	}

	// Marshal explanation data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Cache with expiration
	return e.cache.Set(ctx, key, jsonData, 24*time.Hour).Err()
}
