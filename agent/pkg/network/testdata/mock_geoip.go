package testdata

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

// Sample GeoIP database content - this is a minimal GeoLite2-City database format
var mockGeoIPDB = []byte{
	0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, // Magic bytes
	0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
	// Simplified database structure for testing
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // IPv4 search tree
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Data section with minimal record
	0x7b, 0x22, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72,
	0x79, 0x22, 0x3a, 0x7b, 0x22, 0x69, 0x73, 0x6f,
	0x5f, 0x63, 0x6f, 0x64, 0x65, 0x22, 0x3a, 0x22,
	0x55, 0x53, 0x22, 0x7d, 0x7d,
}

// CreateMockGeoIPDB creates a mock GeoIP database for testing
func CreateMockGeoIPDB() (string, error) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "geoip-test")
	if err != nil {
		return "", err
	}

	dbPath := filepath.Join(tmpDir, "GeoLite2-City.mmdb")
	
	// Write mock database content
	if err := ioutil.WriteFile(dbPath, mockGeoIPDB, 0644); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	return dbPath, nil
}

// CleanupMockGeoIPDB removes the mock GeoIP database
func CleanupMockGeoIPDB(dbPath string) error {
	return os.RemoveAll(filepath.Dir(dbPath))
}