package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	lru "github.com/hashicorp/golang-lru"
	"github.com/hillu/go-yara/v4"
)

// scanCallback implements yara.ScanCallback for collecting matches
type scanCallback struct {
	matches []yara.MatchRule
}

func (sc *scanCallback) RuleMatching(ctx *yara.ScanContext, r *yara.Rule) (bool, error) {
	match := yara.MatchRule{
		Rule:      r.Identifier(),
		Tags:      r.Tags(),
		Strings:   make([]yara.MatchString, 0),
		Metas:     r.Metas(),
	}
	sc.matches = append(sc.matches, match)
	return true, nil
}

// RuleMetadata stores rule metadata
type RuleMetadata struct {
	Version     string    `json:"version"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	LastUpdated time.Time `json:"last_updated"`
	Hash        string    `json:"hash"`         // Hash of rule content
	Severity    string    `json:"severity"`
	Author      string    `json:"author"`
	Tags        []string  `json:"tags"`
}

// RuleInfo stores comprehensive rule information
type RuleInfo struct {
	Path     string       `json:"path"`
	Name     string       `json:"name"`
	Metadata RuleMetadata `json:"metadata"`
	Enabled  bool         `json:"enabled"`
}

// RulesManager handles YARA rules compilation and scanning
type RulesManager struct {
	compiler    *yara.Compiler
	rules       *yara.Rules
	mutex       sync.RWMutex
	rulesDir    string
	rulesInfo   map[string]RuleInfo
	lastUpdated time.Time
	scanCache   *lru.Cache
	ruleCache   *lru.Cache
}

// scanCacheKey combines data hash and rule version for cache key
type scanCacheKey struct {
	dataHash    string
	rulesHash   string
}

// NewManager creates a new YARA rules manager
func NewManager(rulesDir string) (*RulesManager, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create YARA compiler: %v", err)
	}

	// Initialize LRU caches
	scanCache, err := lru.New(10000) // Cache last 10k scan results
	if err != nil {
		return nil, fmt.Errorf("failed to create scan cache: %v", err)
	}

	ruleCache, err := lru.New(1000) // Cache last 1k compiled rules
	if err != nil {
		return nil, fmt.Errorf("failed to create rule cache: %v", err)
	}

	return &RulesManager{
		compiler:    compiler,
		rulesDir:    rulesDir,
		rulesInfo:   make(map[string]RuleInfo),
		scanCache:   scanCache,
		ruleCache:   ruleCache,
	}, nil
}

// extractMetadata extracts metadata from YARA rule file
func (rm *RulesManager) extractMetadata(content string) RuleMetadata {
	metadata := RuleMetadata{
		Version:     "1.0.0",
		LastUpdated: time.Now(),
		Tags:        make([]string, 0),
	}

	// Extract version
	verRegex := regexp.MustCompile(`Version:\s*([0-9]+\.[0-9]+\.[0-9]+)`)
	if matches := verRegex.FindStringSubmatch(content); len(matches) > 1 {
		metadata.Version = matches[1]
	}

	// Extract category
	catRegex := regexp.MustCompile(`Category:\s*(.+)`)
	if matches := catRegex.FindStringSubmatch(content); len(matches) > 1 {
		metadata.Category = strings.TrimSpace(matches[1])
	}

	// Extract description
	descRegex := regexp.MustCompile(`Description:\s*(.+)`)
	if matches := descRegex.FindStringSubmatch(content); len(matches) > 1 {
		metadata.Description = strings.TrimSpace(matches[1])
	}

	// Extract severity
	sevRegex := regexp.MustCompile(`Severity:\s*(.+)`)
	if matches := sevRegex.FindStringSubmatch(content); len(matches) > 1 {
		metadata.Severity = strings.TrimSpace(matches[1])
	}

	// Extract author
	authorRegex := regexp.MustCompile(`Author:\s*(.+)`)
	if matches := authorRegex.FindStringSubmatch(content); len(matches) > 1 {
		metadata.Author = strings.TrimSpace(matches[1])
	}

	// Extract tags
	tagsRegex := regexp.MustCompile(`Tags:\s*(.+)`)
	if matches := tagsRegex.FindStringSubmatch(content); len(matches) > 1 {
		tags := strings.Split(matches[1], ",")
		for _, tag := range tags {
			metadata.Tags = append(metadata.Tags, strings.TrimSpace(tag))
		}
	}

	// Calculate content hash
	hasher := sha256.New()
	hasher.Write([]byte(content))
	metadata.Hash = hex.EncodeToString(hasher.Sum(nil))

	return metadata
}

// AddRuleFile adds and tracks a YARA rule file
func (rm *RulesManager) AddRuleFile(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file %s: %v", path, err)
	}

	metadata := rm.extractMetadata(string(content))
	ruleName := filepath.Base(path)

	rm.rulesInfo[path] = RuleInfo{
		Path:     path,
		Name:     ruleName,
		Metadata: metadata,
		Enabled:  true,
	}

	// Check if we have a cached compilation for this rule hash
	if cached, ok := rm.ruleCache.Get(metadata.Hash); ok {
		rm.rules = cached.(*yara.Rules)
		return nil
	}

	namespace := strings.TrimSuffix(ruleName, filepath.Ext(ruleName))
	if err := rm.compiler.AddString(string(content), namespace); err != nil {
		return fmt.Errorf("failed to compile rule file %s: %v", path, err)
	}

	return nil
}

// CompileRules finalizes rule compilation
func (rm *RulesManager) CompileRules() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rules, err := rm.compiler.GetRules()
	if err != nil {
		return fmt.Errorf("failed to compile rules: %v", err)
	}

	rm.rules = rules
	rm.lastUpdated = time.Now()

	// Cache the compiled rules using concatenated rule hashes as key
	var hashBuilder strings.Builder
	for _, info := range rm.rulesInfo {
		hashBuilder.WriteString(info.Metadata.Hash)
	}
	rm.ruleCache.Add(hashBuilder.String(), rules)

	return nil
}

// ScanData scans data against compiled YARA rules with caching
func (rm *RulesManager) ScanData(data []byte) ([]yara.MatchRule, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	if rm.rules == nil {
		return nil, fmt.Errorf("no rules compiled")
	}

	// Generate cache key
	hasher := sha256.New()
	hasher.Write(data)
	dataHash := hex.EncodeToString(hasher.Sum(nil))

	var rulesHash strings.Builder
	for _, info := range rm.rulesInfo {
		if info.Enabled {
			rulesHash.WriteString(info.Metadata.Hash)
		}
	}

	cacheKey := scanCacheKey{
		dataHash:    dataHash,
		rulesHash:   rulesHash.String(),
	}

	// Check cache
	if cached, ok := rm.scanCache.Get(cacheKey); ok {
		return cached.([]yara.MatchRule), nil
	}

	// Configure scan for better performance
	var scanFlags yara.ScanFlags
	if runtime.GOOS == "windows" {
		scanFlags |= yara.ScanFlagsProcessMemory
	}

	callback := &scanCallback{
		matches: make([]yara.MatchRule, 0),
	}

	// Perform scan with timeout
	err := rm.rules.ScanMem(data, scanFlags, 60*time.Second, callback)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %v", err)
	}

	// Cache results
	rm.scanCache.Add(cacheKey, callback.matches)

	return callback.matches, nil
}

// CheckForUpdates checks rules directory for new or updated rules
func (rm *RulesManager) CheckForUpdates() (bool, error) {
	updated := false
	err := filepath.Walk(rm.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(info.Name(), ".yar") {
			return nil
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		metadata := rm.extractMetadata(string(content))

		existingRule, exists := rm.rulesInfo[path]
		if !exists {
			// New rule found
			updated = true
			return nil
		}

		// Check if content has changed
		if metadata.Hash != existingRule.Metadata.Hash {
			updated = true
			return nil
		}

		// Check if version has changed
		if metadata.Version != existingRule.Metadata.Version {
			v1, _ := version.NewVersion(metadata.Version)
			v2, _ := version.NewVersion(existingRule.Metadata.Version)
			if v1.GreaterThan(v2) {
				updated = true
			}
		}

		return nil
	})

	return updated, err
}

// UpdateRules updates all rules from the rules directory
func (rm *RulesManager) UpdateRules() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Create new compiler for clean slate
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create YARA compiler: %v", err)
	}
	rm.compiler = compiler

	// Clear existing rules info
	rm.rulesInfo = make(map[string]RuleInfo)

	// Walk rules directory and add all rules
	err = filepath.Walk(rm.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(info.Name(), ".yar") {
			return nil
		}

		if err := rm.AddRuleFile(path); err != nil {
			log.Printf("Warning: failed to add rule file %s: %v", path, err)
			return nil
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk rules directory: %v", err)
	}

	return rm.CompileRules()
}

// GetRuleInfo returns information about all loaded rules
func (rm *RulesManager) GetRuleInfo() []RuleInfo {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	rules := make([]RuleInfo, 0, len(rm.rulesInfo))
	for _, info := range rm.rulesInfo {
		rules = append(rules, info)
	}
	return rules
}

// GetLastUpdated returns the timestamp of the last rules update
func (rm *RulesManager) GetLastUpdated() time.Time {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	return rm.lastUpdated
}

// EnableRule enables a specific rule by path
func (rm *RulesManager) EnableRule(path string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rule, exists := rm.rulesInfo[path]; exists {
		rule.Enabled = true
		rm.rulesInfo[path] = rule
		return rm.CompileRules()
	}
	return fmt.Errorf("rule not found: %s", path)
}

// DisableRule disables a specific rule by path
func (rm *RulesManager) DisableRule(path string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rule, exists := rm.rulesInfo[path]; exists {
		rule.Enabled = false
		rm.rulesInfo[path] = rule
		return rm.CompileRules()
	}
	return fmt.Errorf("rule not found: %s", path)
}

// Close releases resources
func (rm *RulesManager) Close() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rm.rules != nil {
		rm.rules.Destroy()
	}
	if rm.compiler != nil {
		rm.compiler.Destroy()
	}
	return nil
}