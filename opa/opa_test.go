package opa

import (
	"context"
	"testing"
)

func engine(t *testing.T, cfg map[string]any) *Engine {
	t.Helper()

	e, err := NewEngine("../policies", false, cfg, map[string]any{"isolation": map[string]any{"mode": "full"}})
	if err != nil {
		t.Fatal(err)
	}

	return e
}

func TestImageVisible(t *testing.T) {
	ctx := context.Background()

	open := engine(t, nil)
	if !open.ImageVisible(ctx, []string{"anything"}) || !open.ImageVisible(ctx, nil) {
		t.Error("unrestricted config must show every image")
	}

	e := engine(t, map[string]any{"allowed_images": []any{"alpine", "myreg.local/*"}})

	for refs, want := range map[string]bool{
		"alpine:3.19":            true,
		"myreg.local/team/app:1": true,
		"alpine@sha256:abc":      true,
		"evil/alpine":            false,
		"sha256:abc":             false,
	} {
		if got := e.ImageVisible(ctx, []string{"sha256:zzz", refs}); got != want {
			t.Errorf("%s: got %v want %v", refs, got, want)
		}
	}

	if e.ImageVisible(ctx, nil) {
		t.Error("untagged image must be hidden when restricted")
	}
}
