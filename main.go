package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/k3a/opa-docker-proxy/config"
	"github.com/k3a/opa-docker-proxy/isolation"
	"github.com/k3a/opa-docker-proxy/logger"
	"github.com/k3a/opa-docker-proxy/opa"
	"github.com/k3a/opa-docker-proxy/proxy"
)

// cliArgs describes the command-line interface.
type cliArgs struct {
	Config        string `arg:"-c"               help:"path to configuration file (default: /etc/opa-docker-proxy/config.yaml, optional)"`
	Isolation     bool   `arg:"-i"               help:"enable isolation (name defaults to CWD hash; use --isolation-name to override)"`
	IsolationName string `arg:"--isolation-name" help:"isolation name (implies -i)"`
}

func (cliArgs) Description() string {
	return "OPA-powered Docker access proxy with optional resource isolation."
}

func main() {
	var args cliArgs
	arg.MustParse(&args)

	// --isolation-name implies -i.
	isolationOn := args.Isolation || args.IsolationName != ""

	// Load configuration.
	cfg, err := config.LoadConfig(args.Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialise structured logging.
	logger.Setup(cfg.Logging.Level, cfg.Logging.Format, os.Stdout)
	slog.Info("starting opa-docker-proxy", "config_file", args.Config)

	// Load OPA policies.
	opaEngine, err := opa.NewEngine(cfg.PoliciesPath, cfg.Logging.LogOPA)
	if err != nil {
		slog.Error("failed to load OPA policies", "error", err)
		os.Exit(1)
	}

	slog.Info("OPA policies loaded", "policies_path", cfg.PoliciesPath)

	// Optional isolation context.
	var iso *isolation.Isolation
	if isolationOn {
		iso, err = isolation.New(args.IsolationName)
		if err != nil {
			slog.Error("failed to create isolation context", "error", err)
			os.Exit(1)
		}

		slog.Info("isolation enabled", "name", iso.Name)
	}

	// Create the proxy.
	p, err := proxy.New(cfg, opaEngine, iso)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		os.Exit(1)
	}

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("shutting down ...")
		p.Stop()
	}()

	// Start serving.
	if err := p.Start(); err != nil {
		slog.Error("proxy stopped", "error", err)
		os.Exit(1)
	}
}
