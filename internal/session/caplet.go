package session

import (
	"fmt"
	"os"
	"path/filepath"
)

// capletDirs is the search path for caplet scripts.
var capletDirs = []string{"caplets", "."}

// RunCaplet executes a caplet script non-interactively.
func (s *Session) RunCaplet(path string) error {
	return s.runCaplet(path)
}

// readCaplet locates and reads a caplet script.
func readCaplet(path string) ([]byte, error) {
	if filepath.IsAbs(path) {
		return os.ReadFile(path)
	}
	for _, dir := range capletDirs {
		full := filepath.Join(dir, path)
		if data, err := os.ReadFile(full); err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("caplet %s not found (looked in %v)", path, capletDirs)
}
