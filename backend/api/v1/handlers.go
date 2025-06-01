package v1

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hillu/go-yara/v4"
	"github.com/smartshieldai-idps/backend/internal/detection/elasticsearch"
	"github.com/smartshieldai-idps/backend/internal/detection/ml"
	"github.com/smartshieldai-idps/backend/internal/detection/rules"
	"github.com/smartshieldai-idps/backend/internal/middleware"
	"github.com/smartshieldai-idps/backend/internal/models"
	"github.com/smartshieldai-idps/backend/internal/store"
)

// Handler handles API requests
type Handler struct {
	store    *store.Store
	rules    *rules.RulesManager
	esLogger *elasticsearch.Logger
	ml       *ml.Service
}

// NewHandler creates a new API handler
func NewHandler(store *store.Store, rules *rules.RulesManager, esLogger *elasticsearch.Logger, mlService *ml.Service) *Handler {
	return &Handler{
		store:    store,
		rules:    rules,
		esLogger: esLogger,
		ml:       mlService,
	}
}

// RegisterRoutes registers API routes
func (h *Handler) RegisterRoutes(r *gin.Engine) {
	v1 := r.Group("/api/v1")
	{
		v1.POST("/data", h.handleDataIngestion)
		v1.GET("/data", h.handleDataRetrieval)
		v1.GET("/threats", h.handleThreatRetrieval)

		// Rules management endpoints
		rules := v1.Group("/rules")
		{
			rules.GET("/status", h.getRulesStatus)
			rules.POST("/update", h.triggerRulesUpdate)
			rules.GET("/list", h.listRules)
		}

		// ML model management endpoints
		ml := v1.Group("/ml")
		{
			ml.GET("/status", h.getMLStatus)
			ml.POST("/retrain", h.triggerMLRetrain)
			ml.GET("/stats", h.getMLStats)
		}
	}
}

// DataIngestionRequest represents the incoming data from agents
type DataIngestionRequest struct {
	AgentID string          `json:"agent_id" binding:"required"`
	Data    models.AgentData `json:"data" binding:"required"`
}

// handleDataIngestion handles incoming data from agents
func (h *Handler) handleDataIngestion(c *gin.Context) {
	var req DataIngestionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set AgentID from request and validate required fields
	if req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	req.Data.AgentID = req.AgentID
	req.Data.Timestamp = time.Now()

	// Convert data to bytes for YARA scanning
	dataBytes, err := json.Marshal(req.Data.RawData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process data"})
		return
	}

	// Scan data for threats using YARA rules
	matches, err := h.rules.ScanData(dataBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan data"})
		return
	}

	// If ML detection is enabled, analyze data for anomalies
	var mlResult *ml.DetectionResult
	if h.ml != nil {
		result, err := h.ml.Predict(req.Data)
		if err != nil {
			log.Printf("Warning: ML detection failed: %v", err)
		} else if result.IsAnomaly {
			severity := "medium"
			if result.Confidence > 0.8 {
				severity = "high"
			}
			// Add ML detection to matches
			matches = append(matches, yara.MatchRule{
				Rule: "ml_anomaly_detection",
				Tags: []string{"ml", "anomaly", result.AnomalyType},
				Metas: []yara.Meta{
					{Identifier: "severity", Value: severity},
					{Identifier: "description", Value: result.Explanation},
					{Identifier: "confidence", Value: result.Confidence},
				},
			})
			mlResult = result
		}
	}

	// If threats detected and ES logger is available, log them
	if len(matches) > 0 && h.esLogger != nil {
		alert := elasticsearch.ThreatAlert{
			Timestamp:   time.Now(),
			AgentID:    req.Data.AgentID,
			RuleName:   matches[0].Rule,
			Severity:   getSeverityFromMatches(matches),
			Description: getDescriptionFromMatches(matches),
			Source:     req.Data,
			MatchData:  json.RawMessage(dataBytes),
		}
		if err := h.esLogger.LogThreat(alert); err != nil {
			// Log the error but don't fail the request
			log.Printf("Warning: failed to log threats: %v", err)
		}

		// If ML detected the anomaly, also log the prevention action
		if mlResult != nil && mlResult.IsAnomaly {
			preventionAction := elasticsearch.PreventionAction{
				Type:      mlResult.AnomalyType,
				Target:    req.Data.Source,
				Timestamp: time.Now(),
				Success:   true,
				Reason:    mlResult.Explanation,
				Metadata: map[string]interface{}{
					"confidence": mlResult.Confidence,
					"source_data": req.Data,
				},
			}
			if err := h.esLogger.LogPreventionAction(preventionAction); err != nil {
				log.Printf("Warning: failed to log prevention action: %v", err)
			}
		}
	}

	// Store the data
	if err := h.store.StoreData(c.Request.Context(), &req.Data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store data"})
		return
	}

	response := gin.H{
		"status":        "success",
		"threats_found": len(matches),
	}

	if len(matches) > 0 {
		response["alert"] = "Threats detected and logged"
		response["severity"] = getSeverityFromMatches(matches)
	}

	if mlResult != nil {
		response["ml_detection"] = mlResult
	}

	c.JSON(http.StatusAccepted, response)
}

// getSeverityFromMatches returns the highest severity from all matches
func getSeverityFromMatches(matches []yara.MatchRule) string {
	highestSeverity := "info"
	severityMap := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	for _, match := range matches {
		for _, meta := range match.Metas {
			if meta.Identifier == "severity" {
				if sev, ok := meta.Value.(string); ok {
					if severityMap[sev] > severityMap[highestSeverity] {
						highestSeverity = sev
					}
				}
			}
		}
	}

	return highestSeverity
}

// getDescriptionFromMatches combines descriptions from all matches
func getDescriptionFromMatches(matches []yara.MatchRule) string {
	var description string
	for i, match := range matches {
		for _, meta := range match.Metas {
			if meta.Identifier == "description" {
				if desc, ok := meta.Value.(string); ok {
					if i > 0 {
						description += "; "
					}
					description += desc
				}
			}
		}
	}
	return description
}

// handleDataRetrieval handles data retrieval requests
func (h *Handler) handleDataRetrieval(c *gin.Context) {
	dataType := c.Query("type")
	if dataType == "" {
		dataType = "all"
	}

	// Parse time range, default to last hour
	since := time.Hour
	if sinceStr := c.Query("since"); sinceStr != "" {
		if d, err := time.ParseDuration(sinceStr); err == nil {
			since = d
		}
	}

	data, err := h.store.GetRecentData(c.Request.Context(), dataType, since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// handleThreatRetrieval handles threat retrieval requests
func (h *Handler) handleThreatRetrieval(c *gin.Context) {
	if h.esLogger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Threat logging is not available"})
		return
	}

	// For now, we'll return a simple response since the ES query implementation would be specific
	c.JSON(http.StatusOK, gin.H{
		"message": "Threat retrieval endpoint ready",
		"status": "available",
	})
}

// RuleStatusResponse represents the rules status response
type RuleStatusResponse struct {
	TotalRules    int                  `json:"totalRules"`
	LastUpdated   string               `json:"lastUpdated"`
	RulesByType   map[string]int       `json:"rulesByType"`
	RuleMetadata  []rules.RuleInfo     `json:"ruleMetadata"`
}

// getRulesStatus returns the current status of YARA rules
func (h *Handler) getRulesStatus(c *gin.Context) {
	ruleInfo := h.rules.GetRuleInfo()
	
	// Aggregate rules by type
	rulesByType := make(map[string]int)
	for _, rule := range ruleInfo {
		ruleType := rule.Metadata.Category
		rulesByType[ruleType]++
	}

	c.JSON(http.StatusOK, middleware.APIResponse{
		Status: "success",
		Data: RuleStatusResponse{
			TotalRules:   len(ruleInfo),
			LastUpdated:  h.rules.GetLastUpdated().Format("2006-01-02 15:04:05"),
			RulesByType:  rulesByType,
			RuleMetadata: ruleInfo,
		},
	})
}

// triggerRulesUpdate triggers a manual update of YARA rules
func (h *Handler) triggerRulesUpdate(c *gin.Context) {
	updated, err := h.rules.CheckForUpdates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.APIResponse{
			Status:  "error",
			Message: "Failed to check for updates: " + err.Error(),
		})
		return
	}

	if !updated {
		c.JSON(http.StatusOK, middleware.APIResponse{
			Status:  "success",
			Message: "Rules are already up to date",
		})
		return
	}

	if err := h.rules.UpdateRules(); err != nil {
		c.JSON(http.StatusInternalServerError, middleware.APIResponse{
			Status:  "error",
			Message: "Failed to update rules: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, middleware.APIResponse{
		Status:  "success",
		Message: "Rules updated successfully",
	})
}

// listRules returns a list of all YARA rules
func (h *Handler) listRules(c *gin.Context) {
	ruleInfo := h.rules.GetRuleInfo()
	c.JSON(http.StatusOK, middleware.APIResponse{
		Status: "success",
		Data:   ruleInfo,
	})
}

// getMLStatus returns the current status of the ML model
func (h *Handler) getMLStatus(c *gin.Context) {
	if h.ml == nil {
		c.JSON(http.StatusServiceUnavailable, middleware.APIResponse{
			Status:  "error",
			Message: "ML detection is not available",
		})
		return
	}

	metrics := h.ml.GetMetrics()
	c.JSON(http.StatusOK, middleware.APIResponse{
		Status: "success",
		Data: gin.H{
			"version":            metrics.Version,
			"last_updated":       metrics.LastMetricsUpdate.Format(time.RFC3339),
			"total_predictions": metrics.TotalPredictions,
			"anomalies_detected": metrics.AnomaliesDetected,
			"accuracy":           metrics.Accuracy,
			"f1_score":          metrics.F1Score,
			"average_latency":    metrics.AverageLatency,
			"false_positives":    metrics.FalsePositives,
			"false_negatives":    metrics.FalseNegatives,
			"drift_score":        metrics.DriftScore,
		},
	})
}

// triggerMLRetrain is a no-op for pre-trained model
func (h *Handler) triggerMLRetrain(c *gin.Context) {
	c.JSON(http.StatusOK, middleware.APIResponse{
		Status:  "success",
		Message: "Pre-trained model does not support retraining",
	})
}

// getMLStats returns detailed statistics about the ML model
func (h *Handler) getMLStats(c *gin.Context) {
	if h.ml == nil {
		c.JSON(http.StatusServiceUnavailable, middleware.APIResponse{
			Status:  "error",
			Message: "ML detection is not available",
		})
		return
	}

	metrics := h.ml.GetMetrics()
	c.JSON(http.StatusOK, middleware.APIResponse{
		Status: "success",
		Data: gin.H{
			"metrics": metrics,
			"model_info": gin.H{
				"architecture": "CNN-BiLSTM",
				"input_size":   h.ml.GetConfig().InputSize,
				"hidden_size":  h.ml.GetConfig().HiddenSize,
				"num_layers":   h.ml.GetConfig().NumLayers,
				"thresholds": gin.H{
					"min_accuracy":    h.ml.GetConfig().MinAccuracy,
					"drift_threshold": h.ml.GetConfig().DriftThreshold,
				},
			},
		},
	})
}