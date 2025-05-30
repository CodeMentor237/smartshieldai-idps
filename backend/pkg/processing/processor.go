package processing

import (
	"log"

	"github.com/smartshieldai-idps/backend/pkg/yara"
)

var yaraScanner *yara.YaraScanner

// InitYaraScanner initializes the YARA scanner with the given rule file
func InitYaraScanner(ruleFile string) error {
	scanner, err := yara.NewYaraScanner(ruleFile)
	if err != nil {
		return err
	}
	yaraScanner = scanner
	return nil
}

// ProcessData scans incoming data for YARA matches and logs/alert on any matches
func ProcessData(data []byte) {
	if yaraScanner == nil {
		log.Println("YARA scanner not initialized")
		return
	}
	matches, err := yaraScanner.ScanData(data)
	if err != nil {
		log.Printf("YARA scan error: %v", err)
		return
	}
	if len(matches) > 0 {
		for _, match := range matches {
			log.Printf("YARA ALERT: Rule=%s Tags=%v", match.Rule, match.Tags)
			// Optionally, send to Elasticsearch:
			// elasticsearch.IndexThreat(match, data)
		}
	}
} 