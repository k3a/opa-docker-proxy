package opa

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

// Engine holds compiled Rego policies and can evaluate them.
type Engine struct {
	prepared rego.PreparedEvalQuery
}

// NewEngine loads all .rego files from the given directory and prepares a
// query for both "allow" and "reason". The policy files must define a rule
// named "allow" that evaluates to true when a request is permitted, and a
// rule named "reason" that provides a human-readable explanation.
func NewEngine(polDir string, allowOPAPrint bool) (*Engine, error) {
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

	// Prepare the query. We query both "allow" and "reason" from the
	// "policies" package so that the host can forward a meaningful
	// explanation when a request is denied.
	r := rego.New(
		rego.Query("result = data.policies.allow; reason = data.policies.reason"),
		rego.Compiler(compiler),
		rego.PrintHook(&slogPrintHook{allowOPAPrint}),
	)

	prepared, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("prepare rego query: %w", err)
	}

	return &Engine{
		prepared: prepared,
	}, nil
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
