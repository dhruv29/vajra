package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The example configurations are documentation. This keeps them valid as the
// configuration format changes.
func TestTheExampleConfigurationsAreValid(t *testing.T) {
	for _, name := range []string{"run.json", "full.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			// The examples name paths that do not exist here; a source root
			// must be a real directory to pass validation.
			if source, ok := m["source"].(map[string]any); ok {
				source["root"] = t.TempDir()
			}
			patched, _ := json.Marshal(m)

			cfg, policy, err := Parse(bytes.NewReader(patched))

			if err != nil {
				t.Fatalf("examples/%s is not a valid configuration: %v", name, err)
			}
			if policy == nil || len(cfg.Targets) == 0 {
				t.Fatalf("examples/%s has no scope or targets", name)
			}
		})
	}
}
