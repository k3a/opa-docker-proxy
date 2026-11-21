package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
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
	Config        string `arg:"-c"               help:"configuration file (default: /etc/opa-docker-proxy/config.yaml if present, else built-in defaults)"`
	Isolation     bool   `arg:"-i"               help:"isolate resources by label; name defaults to the current directory made filename-safe. Listens on a private temp socket and logs to a temp file"`
	IsolationName string `arg:"--isolation-name" help:"use this isolation name instead of the directory-derived name (implies -i)"`
	Socket        string `arg:"-s,--socket"      help:"unix socket to listen on; overrides listen.socket and the -i temp socket"`
	PrintName     bool   `arg:"--print-name"     help:"print the isolation name and exit (for scripts)"`
	PrintSocket   bool   `arg:"--print-socket"   help:"print the socket path that -i uses and exit (for scripts)"`

	Clean *cleanCmd `arg:"subcommand:clean" help:"remove containers, networks, volumes and images of an isolation (current directory's by default)"`
}

// cleanCmd removes isolated objects directly through the Docker socket.
type cleanCmd struct {
	All bool `arg:"--all-isolated" help:"remove objects of every isolation name (any directory), not just the current one"`
}

func (cliArgs) Description() string {
	return "OPA-powered Docker access proxy with optional resource isolation.\n" +
		"Without a command, runs the proxy."
}

func (cliArgs) Epilogue() string {
	return `With -i the socket is $XDG_RUNTIME_DIR/opa-docker-proxy/<name>.sock (or ~/.local/share/opa-docker-proxy/) and logs go to
<name>.log next to it; both are removed on exit.

Examples:
  opa-docker-proxy                          run with the configured socket
  opa-docker-proxy -i &                     run isolated for the current directory
  export DOCKER_HOST=unix://$(opa-docker-proxy --print-socket)
  opa-docker-proxy clean                    remove this directory's isolated objects
  opa-docker-proxy clean --all-isolated     remove every isolated object`
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

	if args.Clean != nil {
		os.Exit(runClean(cfg, args))
	}

	isoName := cfg.Isolation.Name
	if args.IsolationName != "" {
		isoName = args.IsolationName
	}

	// Subcommands for scripts: print the resolved isolation name / socket.
	if args.PrintName || args.PrintSocket {
		iso, err := isolation.New(isoName, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if args.PrintName {
			fmt.Println(iso.Name)
			return
		}

		sock := args.Socket
		if sock == "" {
			if sock, err = isolatedSocketPath(isoName); err != nil {
				fmt.Fprintf(os.Stderr, "error resolving socket path: %v\n", err)
				os.Exit(1)
			}
		}

		fmt.Println(sock)

		return
	}

	// Resolve the listen socket: -s wins. With -i / --isolation-name the
	// socket is always a private per-isolation path in the temp dir (the
	// config's listen.socket is ignored). With isolation enabled only via
	// the config, that path is used when the built-in default socket is set.
	// Whenever -i is given, logs go to <name>.log instead of stdout.
	autoSocket := false

	if args.Socket != "" {
		cfg.Listen.Socket = args.Socket
	} else if isolationOn || (cfg.Isolation.Enabled && cfg.Listen.Socket == config.DefaultSocket) {
		cfg.Listen.Socket, err = isolatedSocketPath(isoName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error resolving socket path: %v\n", err)
			os.Exit(1)
		}

		cfg.Listen.SocketMode = 0o600
		autoSocket = true
	}

	// Initialise structured logging.
	// With -i (or an auto socket), log to <name>.log in the isolation temp
	// directory and remove it on exit.
	var (
		logOut  io.Writer = os.Stdout
		logPath string
	)

	if isolationOn || autoSocket {
		logPath, err = isolatedBasePath(isoName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error resolving log path: %v\n", err)
			os.Exit(1)
		}

		logPath += ".log"

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

// isolatedSocketPath returns <private dir>/<name>.sock, creating the per-user
// parent directory (mode 0700) if needed. Names that
// are not filename-safe are replaced by a hash. An empty name uses the same
// CWD hash as the isolation default, so the path is predictable.
func isolatedSocketPath(name string) (string, error) {
	base, err := isolatedBasePath(name)
	if err != nil {
		return "", err
	}

	return base + ".sock", nil
}

// privateDir returns a per-user directory (mode 0700, owned by the current
// uid) for auto-generated sockets and logs. It prefers $XDG_RUNTIME_DIR and
// falls back to ~/.local/share/opa-docker-proxy. An existing path is accepted
// only if it is a real directory (no symlink) owned by us with no group or
// other access.
func privateDir() (string, error) {
	uid := os.Getuid()

	var dir string
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" && filepath.IsAbs(rt) {
		dir = filepath.Join(rt, "opa-docker-proxy")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		// Create the parents if missing (the leaf is verified below).
		base := filepath.Join(home, ".local", "share")
		if err := os.MkdirAll(base, 0o700); err != nil {
			return "", err
		}

		dir = filepath.Join(base, "opa-docker-proxy")
	}

	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is not a regular directory", dir)
	}

	if int(st.Uid) != uid {
		return "", fmt.Errorf("%s is not owned by the current user", dir)
	}

	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s has insecure permissions %v (want 0700)", dir, fi.Mode().Perm())
	}

	return dir, nil
}

// isolatedBasePath returns <private dir>/<name> without extension.
func isolatedBasePath(name string) (string, error) {
	if name == "" {
		var err error

		name, err = isolation.DefaultName()
		if err != nil {
			return "", err
		}
	}

	if !safeName.MatchString(name) {
		h := sha256.Sum256([]byte(name))
		name = fmt.Sprintf("%x", h[:8])
	}

	dir, err := privateDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, name), nil
}

// runClean implements the clean subcommand and returns the exit code.
func runClean(cfg config.Config, args cliArgs) int {
	name := cfg.Isolation.Name
	if args.IsolationName != "" {
		name = args.IsolationName
	}

	iso, err := isolation.New(name, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return net.Dial("unix", cfg.DockerSocket)
			},
		},
	}

	if args.Clean.All {
		fmt.Println("cleaning all isolated objects (any isolation name)")
	} else {
		fmt.Printf("cleaning objects of isolation %q\n", iso.Name)
	}

	res, err := isolation.Clean(context.Background(), client, iso.Name, args.Clean.All,
		func(t isolation.ResourceType, id string) { fmt.Printf("removed %v %s\n", t, id) })
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fmt.Printf("removed: %d containers, %d networks, %d volumes, %d images\n",
		res.Removed[isolation.ResourceContainer], res.Removed[isolation.ResourceNetwork],
		res.Removed[isolation.ResourceVolume], res.Removed[isolation.ResourceImage])

	for _, f := range res.Failures {
		fmt.Fprintf(os.Stderr, "failed: %s\n", f)
	}

	if len(res.Failures) > 0 {
		return 1
	}

	return 0
}
