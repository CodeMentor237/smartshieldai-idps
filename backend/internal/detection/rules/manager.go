package rules

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"time"

	"github.com/hillu/go-yara/v4"
)

// RulesManager handles YARA rules compilation and scanning
type RulesManager struct {
	compiler *yara.Compiler
	rules    *yara.Rules
	mutex    sync.RWMutex
}

// NewManager creates a new YARA rules manager
func NewManager() (*RulesManager, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create YARA compiler: %v", err)
	}

	return &RulesManager{
		compiler: compiler,
	}, nil
}

// AddRuleFile adds a YARA rule file to the compiler
func (rm *RulesManager) AddRuleFile(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file %s: %v", path, err)
	}

	namespace := filepath.Base(path)
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
	return nil
}

// scanCallback implements the yara.ScanCallback interface
type scanCallback struct {
	matches []yara.MatchRule
}

// RuleMatching implements part of the yara.ScanCallback interface
func (sc *scanCallback) RuleMatching(ctx *yara.ScanContext, r *yara.Rule) (bool, error) {
	match := yara.MatchRule{
		Rule:    r.Identifier(),
		Tags:    r.Tags(),
		Strings: make([]yara.MatchString, 0),
		Metas:   r.Metas(),
	}

	sc.matches = append(sc.matches, match)
	return true, nil // Continue scanning for other matches
}

// ScanData scans data against compiled YARA rules
func (rm *RulesManager) ScanData(data []byte) ([]yara.MatchRule, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	if rm.rules == nil {
		return nil, fmt.Errorf("no rules compiled")
	}

	callback := &scanCallback{
		matches: make([]yara.MatchRule, 0),
	}

	err := rm.rules.ScanMem(data, 0, 60*time.Second, callback)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %v", err)
	}

	return callback.matches, nil
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