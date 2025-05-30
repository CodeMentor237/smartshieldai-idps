package yara

import (
	"fmt"
	"log"
	"os"
	"time"

	yara "github.com/hillu/go-yara/v4"
)

// YaraScanner wraps the YARA compiler and rules
type YaraScanner struct {
	rules *yara.Rules
}

// matchCollector implements yara.ScanCallback to collect matches
type matchCollector struct {
	matches []yara.MatchRule
}

func (mc *matchCollector) RuleMatching(sc *yara.ScanContext, rule *yara.Rule) (bool, error) {
	return true, nil
}
func (mc *matchCollector) RuleNotMatching(sc *yara.ScanContext, rule *yara.Rule) (bool, error) {
	return true, nil
}
func (mc *matchCollector) ScanFinished(sc *yara.ScanContext) error {
	return nil
}
func (mc *matchCollector) ImportModule(sc *yara.ScanContext, moduleName string) ([]byte, error) {
	return nil, nil
}
func (mc *matchCollector) ModuleImported(sc *yara.ScanContext, moduleName string, data []byte) error {
	return nil
}
func (mc *matchCollector) RuleMatchingWithMatch(sc *yara.ScanContext, rule *yara.Rule, match yara.MatchRule) (bool, error) {
	mc.matches = append(mc.matches, match)
	return true, nil
}

// NewYaraScanner compiles YARA rules from a file
func NewYaraScanner(ruleFile string) (*YaraScanner, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create YARA compiler: %w", err)
	}

	f, err := os.Open(ruleFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open YARA rule file: %w", err)
	}
	defer f.Close()

	if err := compiler.AddFile(f, ""); err != nil {
		return nil, fmt.Errorf("failed to add YARA rule file: %w", err)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("failed to compile YARA rules: %w", err)
	}

	return &YaraScanner{rules: rules}, nil
}

// ScanData scans the given data for YARA rule matches
func (y *YaraScanner) ScanData(data []byte) ([]yara.MatchRule, error) {
	mc := &matchCollector{}
	err := y.rules.ScanMem(data, yara.ScanFlagsFastMode, 5*time.Second, mc)
	if err != nil {
		return nil, fmt.Errorf("YARA scan failed: %w", err)
	}
	return mc.matches, nil
}

// Example usage: compile rules and scan data
func ExampleYaraUsage() {
	scanner, err := NewYaraScanner("rules/network/network_attacks.yar")
	if err != nil {
		log.Printf("YARA scanner error: %v", err)
		return
	}

	data := []byte("malicious payload here")
	matches, err := scanner.ScanData(data)
	if err != nil {
		log.Printf("YARA scan error: %v", err)
		return
	}

	for _, match := range matches {
		log.Printf("YARA match: %s", match.Rule)
	}
} 