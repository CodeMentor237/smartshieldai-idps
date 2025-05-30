package ml

import (
	"time"

	"github.com/smartshieldai-idps/backend/internal/models"
)

// ModelConfig represents the configuration for the ML model
type ModelConfig struct {
	InputSize     int           // Size of input features
	HiddenSize    int           // Size of hidden layers
	NumLayers     int           // Number of BiLSTM layers
	DropoutRate   float64       // Dropout rate for regularization
	LearningRate  float64       // Learning rate for training
	BatchSize     int           // Batch size for training
	Epochs        int           // Number of training epochs
	ModelPath     string        // Path to save/load model
	LastUpdated   time.Time     // Last model update timestamp
	Version       string        // Model version
	Accuracy      float64       // Model accuracy
	FalsePositive float64       // False positive rate
	FalseNegative float64       // False negative rate
}

// DetectionResult represents the output of the ML model
type DetectionResult struct {
	IsAnomaly     bool          `json:"is_anomaly"`
	Confidence    float64       `json:"confidence"`
	AnomalyType   string        `json:"anomaly_type,omitempty"`
	Features      []float64     `json:"features,omitempty"`
	Explanation   string        `json:"explanation,omitempty"`
	Timestamp     time.Time     `json:"timestamp"`
	SourceData    models.AgentData `json:"source_data"`
}

// Model represents the ML model interface
type Model interface {
	// Train trains the model on the given dataset
	Train(data []models.AgentData) error

	// Predict makes predictions on new data
	Predict(data models.AgentData) (*DetectionResult, error)

	// Save saves the model to disk
	Save(path string) error

	// Load loads the model from disk
	Load(path string) error

	// GetStats returns model statistics
	GetStats() ModelConfig

	// Update updates the model with new data
	Update(data []models.AgentData) error
}

// NewModel creates a new ML model with the given configuration
func NewModel(config ModelConfig) (Model, error) {
	return NewPretrainedModel(config)
} 