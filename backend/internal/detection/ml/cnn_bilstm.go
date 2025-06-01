package ml

import (
	"fmt"
	"math"
)

// CNNBiLSTMModel implements the neural network architecture
type CNNBiLSTMModel struct {
	// CNN parameters
	convFilters    [][]float64 // Convolutional filters
	convBiases     []float64   // Biases for conv layers
	poolingSize    int         // Max pooling size
	
	// BiLSTM parameters
	forwardWeights  [][]float64 // Forward LSTM weights
	backwardWeights [][]float64 // Backward LSTM weights
	lstmBiases      []float64   // LSTM biases
	hiddenSize      int         // Size of hidden state
	
	// Fully connected layer parameters
	fcWeights []float64 // Fully connected layer weights
	fcBias    float64   // Fully connected layer bias
}

// NewCNNBiLSTMModel creates a new CNN-BiLSTM model instance
func NewCNNBiLSTMModel(config ModelConfig) *CNNBiLSTMModel {
	return &CNNBiLSTMModel{
		convFilters:     make([][]float64, config.ConvFilters),
		convBiases:      make([]float64, config.ConvFilters),
		poolingSize:     config.PoolingSize,
		forwardWeights:  make([][]float64, config.BidirectionalLayers),
		backwardWeights: make([][]float64, config.BidirectionalLayers),
		lstmBiases:      make([]float64, config.BidirectionalLayers*2), // Separate biases for forward/backward
		hiddenSize:      config.HiddenSize,
		fcWeights:       make([]float64, config.HiddenSize*2), // Double size for bidirectional
		fcBias:          0.0,
	}
}

// Forward performs the forward pass through the CNN-BiLSTM network
func (m *CNNBiLSTMModel) Forward(input []float64) ([]float64, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// 1. CNN Layer
	convOutput := m.convolutionLayer(input)
	pooledOutput := m.maxPooling(convOutput)

	// 2. BiLSTM Layer
	lstmForward := m.lstmForward(pooledOutput)
	lstmBackward := m.lstmBackward(pooledOutput)
	
	// Concatenate forward and backward LSTM outputs
	lstmOutput := append(lstmForward, lstmBackward...)

	// 3. Fully Connected Layer
	fcOutput := m.fullyConnected(lstmOutput)

	// 4. Final Activation
	prediction := sigmoid(fcOutput)

	return []float64{prediction}, nil
}

// convolutionLayer applies 1D convolution
func (m *CNNBiLSTMModel) convolutionLayer(input []float64) []float64 {
	output := make([]float64, len(input))
	for i := range output {
		sum := 0.0
		for j, filter := range m.convFilters {
			if i+j < len(input) {
				sum += input[i+j] * filter[0]
			}
		}
		output[i] = sum + m.convBiases[0]
	}
	return output
}

// maxPooling performs max pooling operation
func (m *CNNBiLSTMModel) maxPooling(input []float64) []float64 {
	outputSize := len(input) / m.poolingSize
	output := make([]float64, outputSize)
	
	for i := 0; i < outputSize; i++ {
		start := i * m.poolingSize
		end := start + m.poolingSize
		if end > len(input) {
			end = len(input)
		}
		
		maxVal := input[start]
		for j := start + 1; j < end; j++ {
			if input[j] > maxVal {
				maxVal = input[j]
			}
		}
		output[i] = maxVal
	}
	
	return output
}

// lstmForward processes sequence in forward direction
func (m *CNNBiLSTMModel) lstmForward(input []float64) []float64 {
	hiddenState := make([]float64, m.hiddenSize)
	cellState := make([]float64, m.hiddenSize)
	
	// LSTM computation
	for _, x := range input {
		// Input gate
		inputGate := sigmoid(x*m.forwardWeights[0][0] + m.lstmBiases[0])
		// Forget gate
		forgetGate := sigmoid(x*m.forwardWeights[0][1] + m.lstmBiases[1])
		// Output gate
		outputGate := sigmoid(x*m.forwardWeights[0][2] + m.lstmBiases[2])
		// Cell state
		cellState[0] = forgetGate*cellState[0] + inputGate*tanh(x*m.forwardWeights[0][3])
		// Hidden state
		hiddenState[0] = outputGate * tanh(cellState[0])
	}
	
	return hiddenState
}

// lstmBackward processes sequence in backward direction
func (m *CNNBiLSTMModel) lstmBackward(input []float64) []float64 {
	hiddenState := make([]float64, m.hiddenSize)
	cellState := make([]float64, m.hiddenSize)
	
	// Process input in reverse order
	for i := len(input) - 1; i >= 0; i-- {
		x := input[i]
		// Input gate
		inputGate := sigmoid(x*m.backwardWeights[0][0] + m.lstmBiases[0])
		// Forget gate
		forgetGate := sigmoid(x*m.backwardWeights[0][1] + m.lstmBiases[1])
		// Output gate
		outputGate := sigmoid(x*m.backwardWeights[0][2] + m.lstmBiases[2])
		// Cell state
		cellState[0] = forgetGate*cellState[0] + inputGate*tanh(x*m.backwardWeights[0][3])
		// Hidden state
		hiddenState[0] = outputGate * tanh(cellState[0])
	}
	
	return hiddenState
}

// fullyConnected applies fully connected layer
func (m *CNNBiLSTMModel) fullyConnected(input []float64) float64 {
	var sum float64
	for i, x := range input {
		if i < len(m.fcWeights) {
			sum += x * m.fcWeights[i]
		}
	}
	return sum + m.fcBias
}

// Helper activation functions
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func tanh(x float64) float64 {
	return math.Tanh(x)
}
