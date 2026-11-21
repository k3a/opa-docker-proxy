package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func load(t *testing.T, yaml string) Config {
	t.Helper()

	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func TestIsolationModeValidation(t *testing.T) {
	for _, mode := range []string{"", "full", "writes"} {
		c := DefaultConfig()
		c.Isolation.Mode = mode

		if err := c.Validate(); err != nil {
			t.Errorf("mode %q rejected: %v", mode, err)
		}
	}

	c := DefaultConfig()
	c.Isolation.Mode = "everything"

	if c.Validate() == nil {
		t.Error("bogus mode accepted")
	}
}

func TestUnscopedWriteTokens(t *testing.T) {
	c := load(t, "policy:\n  allow: [containers_create, containers_control, exec, images_pull, images_write]\n")

	got := c.UnscopedWriteTokens(false)
	slices.Sort(got)

	if want := []string{"containers_control", "exec", "images_write"}; !slices.Equal(got, want) {
		t.Errorf("without isolation: %v, want %v", got, want)
	}

	// With isolation only images (never isolated) remain unscoped.
	if got := c.UnscopedWriteTokens(true); !slices.Equal(got, []string{"images_write"}) {
		t.Errorf("with isolation: %v", got)
	}

	if got := load(t, "listen: {socket: /x}\n").UnscopedWriteTokens(false); len(got) != 0 {
		t.Errorf("default config warns: %v", got)
	}
}

func TestDevExampleLoads(t *testing.T) {
	c, err := LoadConfig("../config.dev.yaml.example")
	if err != nil {
		t.Fatal(err)
	}

	if !c.Isolation.Enabled || c.Isolation.Mode != "full" || c.Isolation.Name != "dev" {
		t.Errorf("isolation = %+v", c.Isolation)
	}
}
