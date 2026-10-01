package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/k3a/opa-docker-proxy/config"
	"github.com/k3a/opa-docker-proxy/isolation"
	"github.com/k3a/opa-docker-proxy/logger"
	"github.com/k3a/opa-docker-proxy/opa"
	"github.com/k3a/opa-docker-proxy/proxy"
)

func main() {
	// Parse -i flag manually because it has an *optional* value.
	//   -i           -> isolation on, name derived from CWD hash
	//   -i myname    -> isolation on, custom name
	isolationOn := false
	isolationName := ""
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "-i" {
			isolationOn = true
			// Peek at next arg; if it doesn't start with "-" treat it as the name.
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				isolationName = os.Args[i+1]
				// Remove the name from args so flag.Parse doesn't choke.
				os.Args = append(os.Args[:i+1], os.Args[i+2:]...)
			}
			break
		}
	}

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

	// Optional isolation context.
	var iso *isolation.Isolation
	if isolationOn {
		iso, err = isolation.New(isolationName)
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
