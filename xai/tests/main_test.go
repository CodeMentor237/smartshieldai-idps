package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})
	r.POST("/explain", func(c *gin.Context) {
		var req ExplanationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
			})
			return
		}
		if len(req.InputFeatures) != len(req.FeatureNames) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Number of features and feature names must match",
			})
			return
		}
		explanation := generateExplanation(req)
		c.JSON(http.StatusOK, explanation)
	})
	return r
}

func TestHealthCheck(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
}

func TestExplainPrediction(t *testing.T) {
	router := setupRouter()

	reqBody := ExplanationRequest{
		ModelOutput: ModelOutput{
			Score:      0.85,
			Confidence: 0.9,
		},
		InputFeatures: []float64{1.0, 2.0, 3.0},
		FeatureNames:  []string{"feature1", "feature2", "feature3"},
	}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/explain", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	var response ExplanationResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Explanation)
	assert.Equal(t, 0.9, response.ConfidenceScore)
	assert.Len(t, response.FeatureImportance, 3)
}

func TestExplainPredictionInvalidInput(t *testing.T) {
	router := setupRouter()

	reqBody := ExplanationRequest{
		ModelOutput: ModelOutput{
			Score:      0.85,
			Confidence: 0.9,
		},
		InputFeatures: []float64{1.0, 2.0},  // Mismatched length
		FeatureNames:  []string{"feature1", "feature2", "feature3"},
	}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/explain", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Number of features and feature names must match", response["error"])
} 