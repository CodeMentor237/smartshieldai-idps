package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/smartshieldai-idps/backend/internal/models"
)

// PretrainedModel implements the Model interface using a pre-trained model
type PretrainedModel struct {
	config     ModelConfig
	modelPath  string
	lastUpdate time.Time
	version    string
	accuracy   float64
	fpRate     float64
	fnRate     float64
	
	// CNN-BiLSTM model
	cnnBiLSTM *CNNBiLSTMModel
}

// NewPretrainedModel creates a new pre-trained model instance
func NewPretrainedModel(config ModelConfig) (*PretrainedModel, error) {
	model := &PretrainedModel{
		config:     config,
		modelPath:  config.ModelPath,
		lastUpdate: time.Now(),
		version:    "1.0.0",
		accuracy:   0.85, // Pre-trained model accuracy
		fpRate:     0.15, // Pre-trained model false positive rate
		fnRate:     0.15, // Pre-trained model false negative rate
		cnnBiLSTM:  NewCNNBiLSTMModel(config),
	}

	// Load model weights and biases
	if err := model.Load(config.ModelPath); err != nil {
		return nil, fmt.Errorf("failed to load pre-trained model: %v", err)
	}

	return model, nil
}

// Train is a no-op for pre-trained model
func (m *PretrainedModel) Train(data []models.AgentData) error {
	return nil // Pre-trained model doesn't need training
}

// Predict makes predictions using the pre-trained model
func (m *PretrainedModel) Predict(data models.AgentData) (*DetectionResult, error) {
	// Preprocess input data
	features, err := PreprocessData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to preprocess data: %v", err)
	}

	// Run CNN-BiLSTM model inference
	prediction, err := m.cnnBiLSTM.Forward(features)
	if err != nil {
		return nil, fmt.Errorf("failed to run model inference: %v", err)
	}

	// Postprocess results
	result, err := PostprocessResult(prediction, data)
	if err != nil {
		return nil, fmt.Errorf("failed to postprocess results: %v", err)
	}

	return result, nil
}

// Save saves the model configuration and statistics
func (m *PretrainedModel) Save(path string) error {
	modelData := struct {
		Version    string    `json:"version"`
		LastUpdate time.Time `json:"last_update"`
		Accuracy   float64   `json:"accuracy"`
		FPRate     float64   `json:"fp_rate"`
		FNRate     float64   `json:"fn_rate"`
		CNNBiLSTM  *CNNBiLSTMModel `json:"cnn_bilstm"`
	}{
		Version:    m.version,
		LastUpdate: m.lastUpdate,
		Accuracy:   m.accuracy,
		FPRate:     m.fpRate,
		FNRate:     m.fnRate,
		CNNBiLSTM:  m.cnnBiLSTM,
	}

	data, err := json.Marshal(modelData)
	if err != nil {
		return fmt.Errorf("failed to marshal model data: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write model file: %v", err)
	}

	return nil
}

// Load loads the model configuration and statistics
func (m *PretrainedModel) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read model file: %v", err)
	}

	var modelData struct {
		Version    string    `json:"version"`
		LastUpdate time.Time `json:"last_update"`
		Accuracy   float64   `json:"accuracy"`
		FPRate     float64   `json:"fp_rate"`
		FNRate     float64   `json:"fn_rate"`
		CNNBiLSTM  *CNNBiLSTMModel `json:"cnn_bilstm"`
	}

	if err := json.Unmarshal(data, &modelData); err != nil {
		return fmt.Errorf("failed to unmarshal model data: %v", err)
	}

	m.version = modelData.Version
	m.lastUpdate = modelData.LastUpdate
	m.accuracy = modelData.Accuracy
	m.fpRate = modelData.FPRate
	m.fnRate = modelData.FNRate
	m.cnnBiLSTM = modelData.CNNBiLSTM

	return nil
}

// GetStats returns model statistics
func (m *PretrainedModel) GetStats() ModelConfig {
	return ModelConfig{
		InputSize:     m.config.InputSize,
		HiddenSize:    m.config.HiddenSize,
		NumLayers:     m.config.NumLayers,
		DropoutRate:   m.config.DropoutRate,
		LearningRate:  m.config.LearningRate,
		BatchSize:     m.config.BatchSize,
		Epochs:        m.config.Epochs,
		ModelPath:     m.modelPath,
		LastUpdated:   m.lastUpdate,
		Version:       m.version,
		Accuracy:      m.accuracy,
		FalsePositive: m.fpRate,
		FalseNegative: m.fnRate,
	}
}

// Update is a no-op for pre-trained model
func (m *PretrainedModel) Update(data []models.AgentData) error {
	return nil // Pre-trained model doesn't need updates
}