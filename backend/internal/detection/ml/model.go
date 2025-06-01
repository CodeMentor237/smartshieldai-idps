package ml

import (
	"time"

	"github.com/smartshieldai-idps/backend/internal/models"
)

// ModelConfig represents the configuration for the ML model
type ModelConfig struct {
	// Model architecture
	InputSize      int     // Size of input features
	HiddenSize     int     // Size of hidden layers
	NumLayers      int     // Number of BiLSTM layers
	DropoutRate    float64 // Dropout rate for regularization

	// Training parameters
	LearningRate   float64 // Learning rate for training
	BatchSize      int     // Batch size for training
	Epochs         int     // Number of training epochs

	// Model metadata
	ModelPath      string    // Path to save/load model
	LastUpdated    time.Time // Last model update timestamp
	Version        string    // Model version

	// Performance metrics and thresholds
	Accuracy       float64 // Current model accuracy
	MinAccuracy    float64 // Minimum acceptable accuracy
	FalsePositive  float64 // False positive rate
	FalseNegative  float64 // False negative rate
	DriftThreshold float64 // Maximum acceptable drift score

	// CNN specific parameters
	ConvFilters    int     `json:"conv_filters" yaml:"conv_filters"`         // Number of convolutional filters
	ConvKernelSize int     `json:"conv_kernel_size" yaml:"conv_kernel_size"` // Size of convolutional kernel
	PoolingSize    int     `json:"pooling_size" yaml:"pooling_size"`         // Size of max pooling window

	// BiLSTM specific parameters
	BidirectionalLayers int     `json:"bidirectional_layers" yaml:"bidirectional_layers"` // Number of bidirectional LSTM layers
	LSTMDropoutRate     float64 `json:"lstm_dropout_rate" yaml:"lstm_dropout_rate"`       // LSTM-specific dropout rate
}

// DetectionResult represents the output of the ML model
type DetectionResult struct {
	IsAnomaly      bool          `json:"is_anomaly"`
	IsTruePositive bool          `json:"is_true_positive"`
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