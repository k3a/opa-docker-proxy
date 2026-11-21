package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
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
	Socket        string `arg:"-s,--socket"      help:"unix socket to listen on (overrides listen.socket); with isolation and no socket configured: $TMPDIR/opa-docker-proxy/<name>.sock"`
	PrintSocket   bool   `arg:"--print-socket"   help:"print the resolved socket path to stdout and exit (for scripts)"`
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

	// Resolve the listen socket: -s wins; with isolation and the built-in
	// default socket, use a private per-isolation path in the temp dir.
	// Only then is a <name>.log file used instead of stdout.
	autoSocket := false

	if args.Socket != "" {
		cfg.Listen.Socket = args.Socket
	} else if (isolationOn || cfg.Isolation.Enabled) && cfg.Listen.Socket == config.DefaultSocket {
		name := cfg.Isolation.Name
		if args.IsolationName != "" {
			name = args.IsolationName
		}

		cfg.Listen.Socket, err = isolatedSocketPath(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error resolving socket path: %v\n", err)
			os.Exit(1)
		}

		autoSocket = true
	}

	if args.PrintSocket {
		fmt.Println(cfg.Listen.Socket)
		return
	}

	// Initialise structured logging.
	// In auto-socket (isolation) mode, log to <name>.log next to the socket
	// and remove it on exit.
	var (
		logOut  io.Writer = os.Stdout
		logPath string
	)

	if autoSocket {
		logPath = strings.TrimSuffix(cfg.Listen.Socket, ".sock") + ".log"

		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening log file: %v\n", err)
			os.Exit(1)
		}

		defer f.Close()

		logOut = f
	}

	cleanup := func() {
		if logPath != "" {
			_ = os.Remove(logPath)
		}
	}
	defer cleanup()

	// fail logs the error (also to stderr when the log file is about to be
	// removed, so the caller still sees why), cleans up and exits.
	fail := func(msg string, err error) {
		slog.Error(msg, "error", err)

		if logPath != "" {
			fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
		}

		cleanup()
		os.Exit(1)
	}

	logger.Setup(cfg.Logging.Level, cfg.Logging.Format, logOut)
	slog.Info("starting opa-docker-proxy", "config_file", args.Config)

	// Optional isolation context (config file, or -i / --isolation-name).
	var iso *isolation.Isolation
	if isolationOn || cfg.Isolation.Enabled {
		name := cfg.Isolation.Name
		if args.IsolationName != "" {
			name = args.IsolationName
		}

		iso, err = isolation.New(name, isolation.Mode(cfg.Isolation.Mode))
		if err != nil {
			fail("failed to create isolation context", err)
		}

		slog.Info("isolation enabled", "name", iso.Name, "mode", iso.Mode)
	}

	if tokens := cfg.UnscopedWriteTokens(iso != nil); len(tokens) > 0 {
		slog.Warn("policy.allow lets clients change objects they did not create; "+
			"enable isolation to restrict this to resources created through the proxy", "tokens", tokens)
	}

	// Facts for the policies that users can not configure.
	isolationMode := "off"
	if iso != nil {
		isolationMode = string(iso.Mode)
	}

	runtime := map[string]any{"isolation": map[string]any{"mode": isolationMode}}

	// Load OPA policies.
	opaEngine, err := opa.NewEngine(cfg.PoliciesPath, cfg.Logging.LogOPA, cfg.Policy, runtime)
	if err != nil {
		fail("failed to load OPA policies", err)
	}

	slog.Info("OPA policies loaded", "policies_path", cfg.PoliciesPath)

	if iso != nil {
		// policy.allowed_images also masks pulled (shared) images.
		iso.ImageVisible = func(refs []string) bool {
			return opaEngine.ImageVisible(context.Background(), refs)
		}
	}

	// Create the proxy.
	p, err := proxy.New(cfg, opaEngine, iso)
	if err != nil {
		fail("failed to create proxy", err)
	}

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	stopping := make(chan struct{})

	go func() {
		<-sigCh
		close(stopping)
		slog.Info("shutting down ...")
		p.Stop()
	}()

	// Start serving.
	// Closing the unix listener also unlinks the socket file.
	if err := p.Start(); err != nil {
		select {
		case <-stopping:
			return // clean shutdown on signal
		default:
		}

		fail("proxy stopped", err)
	}
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// isolatedSocketPath returns $TMPDIR/opa-docker-proxy/<name>.sock, creating the shared
// parent directory (world-writable + sticky, like /tmp) if needed. Names that
// are not filename-safe are replaced by a hash. An empty name uses the same
// CWD hash as the isolation default, so the path is predictable.
func isolatedSocketPath(name string) (string, error) {
	if name == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}

		h := sha256.Sum256([]byte(cwd))
		name = fmt.Sprintf("%x", h[:8])
	} else if !safeName.MatchString(name) {
		h := sha256.Sum256([]byte(name))
		name = fmt.Sprintf("%x", h[:8])
	}

	dir := filepath.Join(os.TempDir(), "opa-docker-proxy")
	if err := os.MkdirAll(dir, 0o1777); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}

	_ = os.Chmod(dir, 0o1777) // MkdirAll is subject to umask; ignore if not owner

	return filepath.Join(dir, name+".sock"), nil
}
