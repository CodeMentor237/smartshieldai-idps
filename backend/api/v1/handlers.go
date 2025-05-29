package v1

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hillu/go-yara/v4"
	"github.com/smartshieldai-idps/backend/internal/detection/elasticsearch"
	"github.com/smartshieldai-idps/backend/internal/detection/rules"
	"github.com/smartshieldai-idps/backend/internal/models"
	"github.com/smartshieldai-idps/backend/internal/store"
)

// Handler handles API requests
type Handler struct {
	store    *store.Store
	rules    *rules.RulesManager
	esLogger *elasticsearch.Logger
}

// NewHandler creates a new API handler
func NewHandler(store *store.Store, rules *rules.RulesManager, esLogger *elasticsearch.Logger) *Handler {
	return &Handler{
		store:    store,
		rules:    rules,
		esLogger: esLogger,
	}
}

// RegisterRoutes registers API routes
func (h *Handler) RegisterRoutes(r *gin.Engine) {
	v1 := r.Group("/api/v1")
	{
		v1.POST("/data", h.handleDataIngestion)
		v1.GET("/data", h.handleDataRetrieval)
		v1.GET("/threats", h.handleThreatRetrieval)
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

	// Scan data for threats
	matches, err := h.rules.ScanData(dataBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan data"})
		return
	}

	// If threats detected and ES logger is available, log them
	if len(matches) > 0 && h.esLogger != nil {
		if err := h.esLogger.LogThreat(c.Request.Context(), &req.Data, matches); err != nil {
			// Log the error but don't fail the request
			log.Printf("Warning: failed to log threats: %v", err)
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