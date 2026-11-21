package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

// Engine holds compiled Rego policies and can evaluate them.
type Engine struct {
	prepared rego.PreparedEvalQuery
	// imageVisible evaluates data.policies.image_visible(input.refs).
	imageVisible rego.PreparedEvalQuery
}

// NewEngine loads all .rego files from the given directory and prepares a
// query for both "allow" and "reason". The policy files must define a rule
// named "allow" that evaluates to true when a request is permitted, and a
// rule named "reason" that provides a human-readable explanation.
//
// policyConfig is exposed to the policies as data.config. The policies
// validate it and report problems in data.policies.config_errors; a non-empty
// set makes NewEngine fail.
//
// runtime is exposed as data.runtime: facts determined by the proxy itself
// (e.g. the isolation mode) that policies may depend on but users can not set.
func NewEngine(polDir string, allowOPAPrint bool, policyConfig, runtime map[string]any) (*Engine, error) {
	regoFiles, err := findRegoFiles(polDir)
	if err != nil {
		return nil, fmt.Errorf("find rego files in %s: %w", polDir, err)
	}

	if len(regoFiles) == 0 {
		return nil, fmt.Errorf("no .rego files found in %s", polDir)
	}

	// Read all rego modules.
	modules := make(map[string]string, len(regoFiles))
	for _, path := range regoFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rego file %s: %w", path, err)
		}

		modules[path] = string(data)
	}

	// Compile the modules.
	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		EnablePrintStatements: true,
	})
	if err != nil {
		return nil, fmt.Errorf("compile rego modules: %w", err)
	}

	store, err := newStore(policyConfig, runtime)
	if err != nil {
		return nil, err
	}

	if err := checkConfig(compiler, store, len(policyConfig) > 0); err != nil {
		return nil, err
	}

	// Prepare the query. We query both "allow" and "reason" from the
	// "policies" package so that the host can forward a meaningful
	// explanation when a request is denied.
	r := rego.New(
		rego.Query("result = data.policies.allow; reason = data.policies.reason"),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.PrintHook(&slogPrintHook{allowOPAPrint}),
	)

	prepared, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("prepare rego query: %w", err)
	}

	visible, err := rego.New(
		rego.Query("visible = data.policies.image_visible(input.refs)"),
		rego.Compiler(compiler),
		rego.Store(store),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("prepare image visibility query: %w", err)
	}

	return &Engine{
		prepared:     prepared,
		imageVisible: visible,
	}, nil
}

// newStore builds a store holding data.config and data.runtime.
func newStore(policyConfig, runtime map[string]any) (storage.Store, error) {
	if policyConfig == nil {
		policyConfig = map[string]any{}
	}

	if runtime == nil {
		runtime = map[string]any{}
	}

	// Round-trip through JSON so that YAML-decoded values (e.g. int) become
	// plain JSON types the store accepts.
	raw, err := json.Marshal(map[string]any{"config": policyConfig, "runtime": runtime})
	if err != nil {
		return nil, fmt.Errorf("encode policy data: %w", err)
	}

	var normalized map[string]any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, fmt.Errorf("decode policy data: %w", err)
	}

	return inmem.NewFromObject(normalized), nil
}

// checkConfig fails when the policies report errors for the given config.
//
// If config is non-empty but the policies do not define config_errors at all
// (e.g. an outdated policy set), the config would be silently ignored, so
// that is an error too.
func checkConfig(compiler *ast.Compiler, store storage.Store, haveConfig bool) error {
	ctx := context.Background()

	q, err := rego.New(
		rego.Query("data.policies.config_errors"),
		rego.Compiler(compiler),
		rego.Store(store),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("prepare config validation: %w", err)
	}

	rs, err := q.Eval(ctx)
	if err != nil {
		return fmt.Errorf("validate policy config: %w", err)
	}

	if len(rs) == 0 && haveConfig {
		return fmt.Errorf("policy config given, but the loaded policies do not support it " +
			"(data.policies.config_errors is undefined) — are the policy files outdated?")
	}

	var msgs []string

	for _, r := range rs {
		for _, e := range r.Expressions {
			if list, ok := e.Value.([]any); ok {
				for _, m := range list {
					msgs = append(msgs, fmt.Sprint(m))
				}
			}
		}
	}

	if len(msgs) > 0 {
		sort.Strings(msgs)

		return fmt.Errorf("invalid policy config: %s", strings.Join(msgs, "; "))
	}

	return nil
}

// EvalResult is the outcome of a policy evaluation.
type EvalResult struct {
	Allowed bool
	Reason  string
}

// Evaluate runs the OPA policy against the given input.
// The input map must contain the keys: method, path, body, headers, client_ip.
// If a system error occurs (compilation, evaluation) an error is returned and
// the request should be denied.
func (e *Engine) Evaluate(ctx context.Context, input map[string]any) (*EvalResult, error) {
	results, err := e.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("opa eval: %w", err)
	}

	// If no results, the rule didn't evaluate to anything — deny by default.
	if len(results) == 0 {
		return &EvalResult{Allowed: false, Reason: "no policy decision (default deny)"}, nil
	}

	// The last result's bindings carry the variable values.
	result := results[len(results)-1]

	allowVal, ok := result.Bindings["result"]
	if !ok {
		return &EvalResult{Allowed: false, Reason: "policy did not return a result"}, nil
	}

	allowed, err := boolVal(allowVal)
	if err != nil {
		return &EvalResult{Allowed: false, Reason: fmt.Sprintf("policy error: %v", err)}, nil
	}

	// Extract reason from bindings (always available thanks to default rule).
	reason := "denied by policy"

	if reasonRaw, ok := result.Bindings["reason"]; ok {
		if s, ok := reasonRaw.(string); ok {
			reason = s
		}
	}

	if allowed {
		return &EvalResult{Allowed: true, Reason: reason}, nil
	}

	return &EvalResult{Allowed: false, Reason: reason}, nil
}

// ImageVisible reports whether an image with the given references (the name
// used, its repo tags and digests) is acceptable under policy.allowed_images.
// Any error is treated as "not visible".
func (e *Engine) ImageVisible(ctx context.Context, refs []string) bool {
	if refs == nil {
		refs = []string{}
	}

	rs, err := e.imageVisible.Eval(ctx, rego.EvalInput(map[string]any{"refs": refs}))
	if err != nil {
		slog.Error("image visibility evaluation failed", "error", err)

		return false
	}

	return len(rs) > 0 && rs[0].Bindings["visible"] == true
}

// findRegoFiles returns all .rego files in dir (non-recursive).
func findRegoFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		if strings.HasSuffix(e.Name(), ".rego") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

	return files, nil
}

// slogPrintHook implements print.Hook and routes OPA print() output to slog.
// The Location field in print.Context is intentionally omitted from the log
// call — it can be added if you want per-print-call source references.
type slogPrintHook struct {
	allowOPAPrint bool
}

func (h *slogPrintHook) Print(_ print.Context, msg string) error {
	slog.Info("opa print", "output", msg)

	return nil
}

// boolVal extracts a boolean from an arbitrary any value.
func boolVal(v any) (bool, error) {
	switch b := v.(type) {
	case bool:
		return b, nil
	case int64:
		return b != 0, nil
	case float64:
		return b != 0, nil
	case string:
		return strings.EqualFold(b, "true") || b == "1", nil
	default:
		return false, fmt.Errorf("unexpected type %T for allow value", v)
	}
}
