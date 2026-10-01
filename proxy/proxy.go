package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/k3a/opa-docker-proxy/config"
	"github.com/k3a/opa-docker-proxy/isolation"
	"github.com/k3a/opa-docker-proxy/logger"
	"github.com/k3a/opa-docker-proxy/opa"
)

// Proxy is an HTTP reverse proxy that evaluates OPA policies before forwarding
// requests to the Docker daemon.
type Proxy struct {
	config   config.Config
	opa      *opa.Engine
	rproxy   *httputil.ReverseProxy
	listener net.Listener

	// dockerClient is used for internal API calls to Docker (e.g. isolation checks).
	// It shares the same transport as rproxy.
	dockerClient *http.Client

	// Isolation is an optional isolation context. When non-nil, created
	// resources are labelled, list operations are filtered, and access to
	// individual resources is checked. This field is nil when isolation is
	// not enabled, making all the mediation in ServeHTTP a no-op.
	Isolation *isolation.Isolation
}

// New creates a new Proxy.  iso may be nil when isolation is not desired.
func New(cfg config.Config, opaEngine *opa.Engine, iso *isolation.Isolation) (*Proxy, error) {
	// Shared transport that dials the Docker Unix socket.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", cfg.DockerSocket)
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}

	// Create client for internal Docker API calls (isolation checks).
	dockerClient := &http.Client{
		Timeout:   0,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Closure helper for logging — avoids capturing an uninitialized p.
	logAllowed := cfg.Logging.LogAllowed

	rproxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// The URL must have a valid scheme + host for the ReverseProxy to
			// work correctly.  The actual dial is done by the transport above,
			// so the host is ignored.
			req.URL.Scheme = "http"
			req.URL.Host = "docker"
			// Path and RawQuery are preserved from the original request.
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			// Log the response (NOT called for 101 upgrade responses).
			if logAllowed {
				clientIP, _ := resp.Request.Context().Value(clientIPKey).(string)
				if clientIP == "" {
					clientIP = "@"
				}
				logPath := resp.Request.URL.RequestURI()
				if logPath == "" {
					logPath = resp.Request.URL.Path
				}
				logger.LogRequest(true, clientIP, resp.Request.Method, logPath, resp.StatusCode, resp.Request.UserAgent())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("reverse proxy error", "error", err, "method", r.Method, "path", r.URL.Path)
			http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		},
	}

	return &Proxy{
		config:       cfg,
		opa:          opaEngine,
		Isolation:    iso,
		rproxy:       rproxy,
		dockerClient: dockerClient,
	}, nil
}

// context key for storing the client IP in the request context.
type contextKey string

const clientIPKey contextKey = "client_ip"

// conn wraps a net.Conn and logs when it is opened / closed.
type loggingConn struct {
	net.Conn
	id uint64
}

var connCounter uint64

func (c *loggingConn) Close() error {
	slog.Debug("connection closed", "conn_id", c.id)
	return c.Conn.Close()
}

// loggingListener wraps a net.Listener and wraps every accepted connection
// with a loggingConn.
type loggingListener struct {
	net.Listener
}

func (l *loggingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	connCounter++
	id := connCounter
	slog.Debug("connection accepted", "conn_id", id, "local", conn.LocalAddr(), "remote", conn.RemoteAddr())
	return &loggingConn{Conn: conn, id: id}, nil
}

// Start begins listening and serving.
func (p *Proxy) Start() error {
	var l net.Listener
	var err error
	addr := p.config.Listen.Address
	socket := p.config.Listen.Socket

	switch {
	case socket != "":
		if err := removeSocket(socket); err != nil {
			return fmt.Errorf("remove old socket %s: %w", socket, err)
		}
		l, err = net.Listen("unix", socket)
		if err != nil {
			return fmt.Errorf("listen on unix socket %s: %w", socket, err)
		}
		if err := os.Chmod(socket, 0666); err != nil {
			l.Close()
			return fmt.Errorf("set socket permissions %s: %w", socket, err)
		}
		slog.Info("listening on unix socket", "socket", socket)

	case addr != "":
		l, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on tcp %s: %w", addr, err)
		}
		slog.Info("listening on tcp", "address", addr)
	}

	p.listener = &loggingListener{Listener: l}

	srv := &http.Server{
		Handler:      p,
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	return srv.Serve(p.listener)
}

// Stop gracefully closes the listener.
func (p *Proxy) Stop() {
	if p.listener != nil {
		p.listener.Close()
	}
}

// logAndDeny logs a denied request and sends an HTTP error response.
func (p *Proxy) logAndDeny(w http.ResponseWriter, clientIP, method, logPath string, status int, userAgent, body string) {
	if p.config.Logging.LogDenied {
		logger.LogRequest(false, clientIP, method, logPath, status, userAgent)
	}
	http.Error(w, body, status)
}

// ServeHTTP implements http.Handler. It intercepts each request, evaluates the
// OPA policy, and either forwards to Docker or returns 403.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logPath := r.URL.RequestURI()
	if logPath == "" {
		logPath = r.URL.Path
	}

	slog.Debug("=== ServeHTTP begin ===", "method", r.Method, "path", r.URL.Path, "rawquery", r.URL.RawQuery, "proto", r.Proto)

	// ---- 1. Read body ----
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		slog.Error("read body", "error", err)
		http.Error(w, "cannot read request body", http.StatusInternalServerError)
		return
	}
	// Replace the body so the ReverseProxy can read it.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	slog.Debug("request body read", "method", r.Method, "path", r.URL.Path, "body_size", len(bodyBytes))

	// ---- 2. Determine client IP ----
	clientIP := extractClientIP(r)
	// Store in context so ModifyResponse can access it.
	ctx = context.WithValue(ctx, clientIPKey, clientIP)
	*r = *r.WithContext(ctx)

	// ---- 3. Build OPA input ----
	input := buildOPAInput(r, bodyBytes, clientIP)

	// ---- 4. Validate JSON body if applicable ----
	ct := r.Header.Get("Content-Type")
	if len(bodyBytes) > 0 && strings.HasPrefix(ct, "application/json") {
		if !json.Valid(bodyBytes) {
			p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusBadRequest, r.UserAgent(), "invalid JSON in request body")
			return
		}
		var parsed interface{}
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusBadRequest, r.UserAgent(), fmt.Sprintf("cannot parse request body as JSON: %v", err))
			return
		}
		input["body"] = parsed
	}

	// ---- 5. Evaluate OPA policy ----
	result, err := p.opa.Evaluate(ctx, input)
	if err != nil {
		slog.Error("opa evaluation error", "error", err, "client_ip", clientIP, "method", r.Method, "path", r.URL.Path)
		p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusInternalServerError, r.UserAgent(), fmt.Sprintf("policy evaluation error: %v", err))
		return
	}

	slog.Debug("OPA decision", "method", r.Method, "path", r.URL.Path, "allowed", result.Allowed, "reason", result.Reason)

	if !result.Allowed {
		p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusForbidden, r.UserAgent(), result.Reason)
		return
	}

	// ---- 5b. Optional isolation mediation ----
	if p.Isolation != nil {
		p.Isolation.TransformRequest(r)
		if err := p.Isolation.CheckAccess(ctx, p.dockerClient, r.URL.Path); err != nil {
			slog.Warn("isolation check failed", "error", err, "path", r.URL.Path)
			p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusForbidden, r.UserAgent(), err.Error())
			return
		}
	}

	// ---- 6. For upgrade requests (attach, exec), log before forwarding ----
	// The ReverseProxy handles upgrades natively (hijack + bridge) but its
	// ModifyResponse callback is NOT invoked for 101 responses. We log here.
	isUpgrade := isUpgradeRequest(r)
	if isUpgrade {
		slog.Debug("forwarding upgrade request via ReverseProxy", "method", r.Method, "path", r.URL.Path)
		// Log the request now; we expect 101 Switching Protocols.
		if p.config.Logging.LogAllowed {
			logger.LogRequest(true, clientIP, r.Method, logPath, 101, r.UserAgent())
		}
	}

	// ---- 7. Forward using ReverseProxy ----
	// Go's httputil.ReverseProxy handles everything:
	//   - Normal requests: forwards, copies response headers/body
	//   - Upgrade requests (101): hijacks both connections, bridges them
	//   - Hop-by-hop header removal
	//   - Content-Length handling
	//   - Chunked transfer encoding
	p.rproxy.ServeHTTP(w, r)

	slog.Debug("=== ServeHTTP end ===", "method", r.Method, "path", r.URL.Path)
}

// buildOPAInput constructs the input map for OPA evaluation.
func buildOPAInput(r *http.Request, bodyBytes []byte, clientIP string) map[string]interface{} {
	input := map[string]interface{}{
		"method":    r.Method,
		"path":      r.URL.Path,
		"body":      string(bodyBytes),
		"headers":   flattenHeaders(r.Header),
		"client_ip": clientIP,
	}
	return input
}

// flattenHeaders converts http.Header to a map[string]string (first value per key).
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// extractClientIP attempts to extract the real client IP.
func extractClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if real := r.Header.Get("X-Real-Ip"); real != "" {
		return real
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isUpgradeRequest checks if the Docker client is requesting an HTTP upgrade
// (used by attach, exec, etc.).
func isUpgradeRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "Upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "tcp")
}

// removeSocket removes a Unix socket file if it exists.
func removeSocket(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return os.Remove(path)
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
