package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector collects and tracks system metrics
type MetricsCollector struct {
	// Data Collection Metrics
	dataCollectionCount    uint64
	dataCollectionLatency  int64
	dataCollectionErrors   uint64
	dataCollectionDropped  uint64

	// ML Detection Metrics
	mlDetectionCount      uint64
	mlDetectionLatency    int64
	mlDetectionErrors     uint64
	mlFalsePositives      uint64
	mlFalseNegatives      uint64

	// Prevention Metrics
	preventionActionCount uint64
	preventionLatency     int64
	preventionErrors      uint64
	preventionRollbacks   uint64

	// Storage Metrics
	storageWriteCount     uint64
	storageWriteLatency   int64
	storageWriteErrors    uint64
	storageReadCount      uint64
	storageReadLatency    int64
	storageReadErrors     uint64

	// System Metrics
	startTime             time.Time
	mu                    sync.RWMutex
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		startTime: time.Now(),
	}
}

// RecordDataCollection records data collection metrics
func (m *MetricsCollector) RecordDataCollection(latency time.Duration, err error, dropped bool) {
	atomic.AddUint64(&m.dataCollectionCount, 1)
	atomic.AddInt64(&m.dataCollectionLatency, latency.Milliseconds())

	if err != nil {
		atomic.AddUint64(&m.dataCollectionErrors, 1)
	}

	if dropped {
		atomic.AddUint64(&m.dataCollectionDropped, 1)
	}
}

// RecordMLDetection records ML detection metrics
func (m *MetricsCollector) RecordMLDetection(latency time.Duration, err error, isFalsePositive, isFalseNegative bool) {
	atomic.AddUint64(&m.mlDetectionCount, 1)
	atomic.AddInt64(&m.mlDetectionLatency, latency.Milliseconds())

	if err != nil {
		atomic.AddUint64(&m.mlDetectionErrors, 1)
	}

	if isFalsePositive {
		atomic.AddUint64(&m.mlFalsePositives, 1)
	}

	if isFalseNegative {
		atomic.AddUint64(&m.mlFalseNegatives, 1)
	}
}

// RecordPreventionAction records prevention action metrics
func (m *MetricsCollector) RecordPreventionAction(latency time.Duration, err error, rolledBack bool) {
	atomic.AddUint64(&m.preventionActionCount, 1)
	atomic.AddInt64(&m.preventionLatency, latency.Milliseconds())

	if err != nil {
		atomic.AddUint64(&m.preventionErrors, 1)
	}

	if rolledBack {
		atomic.AddUint64(&m.preventionRollbacks, 1)
	}
}

// RecordStorageWrite records storage write metrics
func (m *MetricsCollector) RecordStorageWrite(latency time.Duration, err error) {
	atomic.AddUint64(&m.storageWriteCount, 1)
	atomic.AddInt64(&m.storageWriteLatency, latency.Milliseconds())

	if err != nil {
		atomic.AddUint64(&m.storageWriteErrors, 1)
	}
}

// RecordStorageRead records storage read metrics
func (m *MetricsCollector) RecordStorageRead(latency time.Duration, err error) {
	atomic.AddUint64(&m.storageReadCount, 1)
	atomic.AddInt64(&m.storageReadLatency, latency.Milliseconds())

	if err != nil {
		atomic.AddUint64(&m.storageReadErrors, 1)
	}
}

// GetMetrics returns the current metrics
func (m *MetricsCollector) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uptime := time.Since(m.startTime)

	return map[string]interface{}{
		"uptime": uptime.Seconds(),
		"data_collection": map[string]interface{}{
			"count":    atomic.LoadUint64(&m.dataCollectionCount),
			"latency":  atomic.LoadInt64(&m.dataCollectionLatency),
			"errors":   atomic.LoadUint64(&m.dataCollectionErrors),
			"dropped":  atomic.LoadUint64(&m.dataCollectionDropped),
		},
		"ml_detection": map[string]interface{}{
			"count":           atomic.LoadUint64(&m.mlDetectionCount),
			"latency":         atomic.LoadInt64(&m.mlDetectionLatency),
			"errors":          atomic.LoadUint64(&m.mlDetectionErrors),
			"false_positives": atomic.LoadUint64(&m.mlFalsePositives),
			"false_negatives": atomic.LoadUint64(&m.mlFalseNegatives),
		},
		"prevention": map[string]interface{}{
			"count":     atomic.LoadUint64(&m.preventionActionCount),
			"latency":   atomic.LoadInt64(&m.preventionLatency),
			"errors":    atomic.LoadUint64(&m.preventionErrors),
			"rollbacks": atomic.LoadUint64(&m.preventionRollbacks),
		},
		"storage": map[string]interface{}{
			"write": map[string]interface{}{
				"count":   atomic.LoadUint64(&m.storageWriteCount),
				"latency": atomic.LoadInt64(&m.storageWriteLatency),
				"errors":  atomic.LoadUint64(&m.storageWriteErrors),
			},
			"read": map[string]interface{}{
				"count":   atomic.LoadUint64(&m.storageReadCount),
				"latency": atomic.LoadInt64(&m.storageReadLatency),
				"errors":  atomic.LoadUint64(&m.storageReadErrors),
			},
		},
	}
}

// Reset resets all metrics to zero
func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.StoreUint64(&m.dataCollectionCount, 0)
	atomic.StoreInt64(&m.dataCollectionLatency, 0)
	atomic.StoreUint64(&m.dataCollectionErrors, 0)
	atomic.StoreUint64(&m.dataCollectionDropped, 0)

	atomic.StoreUint64(&m.mlDetectionCount, 0)
	atomic.StoreInt64(&m.mlDetectionLatency, 0)
	atomic.StoreUint64(&m.mlDetectionErrors, 0)
	atomic.StoreUint64(&m.mlFalsePositives, 0)
	atomic.StoreUint64(&m.mlFalseNegatives, 0)

	atomic.StoreUint64(&m.preventionActionCount, 0)
	atomic.StoreInt64(&m.preventionLatency, 0)
	atomic.StoreUint64(&m.preventionErrors, 0)
	atomic.StoreUint64(&m.preventionRollbacks, 0)

	atomic.StoreUint64(&m.storageWriteCount, 0)
	atomic.StoreInt64(&m.storageWriteLatency, 0)
	atomic.StoreUint64(&m.storageWriteErrors, 0)
	atomic.StoreUint64(&m.storageReadCount, 0)
	atomic.StoreInt64(&m.storageReadLatency, 0)
	atomic.StoreUint64(&m.storageReadErrors, 0)

	m.startTime = time.Now()
} 