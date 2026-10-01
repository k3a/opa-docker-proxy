package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/k3a/opa-docker-proxy/config"
	"github.com/k3a/opa-docker-proxy/logger"
	"github.com/k3a/opa-docker-proxy/opa"
	"github.com/k3a/opa-docker-proxy/proxy"
)

func main() {
	configPath := flag.String("c", "/etc/opa-docker-proxy/config.yaml", "path to configuration file")
	flag.Parse()

	// Load configuration.
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialise structured logging.
	logger.Setup(cfg.Logging.Level, cfg.Logging.Format, os.Stdout)
	slog.Info("starting opa-docker-proxy", "config_file", *configPath)

	// Load OPA policies.
	opaEngine, err := opa.NewEngine(cfg.PoliciesPath)
	if err != nil {
		slog.Error("failed to load OPA policies", "error", err)
		os.Exit(1)
	}
	slog.Info("OPA policies loaded", "policies_path", cfg.PoliciesPath)

	// Create the proxy.
	p, err := proxy.New(cfg, opaEngine)
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
