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
	"net/url"
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
	client   *http.Client
	listener net.Listener

	// Isolation is an optional isolation context. When non-nil, created
	// resources are labelled, list operations are filtered, and access to
	// individual resources is checked. This field is nil when isolation is
	// not enabled, making all the mediation in ServeHTTP a no-op.
	Isolation *isolation.Isolation
}

// New creates a new Proxy.  iso may be nil when isolation is not desired.
func New(cfg config.Config, opaEngine *opa.Engine, iso *isolation.Isolation) (*Proxy, error) {
	p := &Proxy{
		config:    cfg,
		opa:       opaEngine,
		Isolation: iso,
		client: &http.Client{
			Timeout: 0, // no timeout for streaming operations (attach, logs, etc.)
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", cfg.DockerSocket)
				},
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
		},
	}

	return p, nil
}

// Start begins listening and serving.
func (p *Proxy) Start() error {
	var l net.Listener
	var err error
	addr := p.config.Listen.Address
	socket := p.config.Listen.Socket

	switch {
	case socket != "":
		// Remove existing socket file, if any.
		if err := removeSocket(socket); err != nil {
			return fmt.Errorf("remove old socket %s: %w", socket, err)
		}
		l, err = net.Listen("unix", socket)
		if err != nil {
			return fmt.Errorf("listen on unix socket %s: %w", socket, err)
		}
		// Make the socket accessible.
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

	p.listener = l

	srv := &http.Server{
		Handler:      p,
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	return srv.Serve(l)
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

// logAllowed logs an allowed request.
func (p *Proxy) logAllowed(clientIP, method, logPath string, status int, userAgent string) {
	if p.config.Logging.LogAllowed {
		logger.LogRequest(true, clientIP, method, logPath, status, userAgent)
	}
}

// ServeHTTP implements http.Handler. It intercepts each request, evaluates the
// OPA policy, and either forwards to Docker or returns 403.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logPath := r.URL.RequestURI()
	if logPath == "" {
		logPath = r.URL.Path
	}

	// ---- 1. Read body ----
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		slog.Error("read body", "error", err)
		http.Error(w, "cannot read request body", http.StatusInternalServerError)
		return
	}
	// Replace the body so upstream can read it.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// ---- 2. Determine client IP ----
	clientIP := extractClientIP(r)

	// ---- 3. Build OPA input ----
	input := buildOPAInput(r, bodyBytes, clientIP)

	// ---- 4. Validate JSON body if applicable ----
	ct := r.Header.Get("Content-Type")
	if len(bodyBytes) > 0 && strings.HasPrefix(ct, "application/json") {
		if !json.Valid(bodyBytes) {
			p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusBadRequest, r.UserAgent(), "invalid JSON in request body")
			return
		}
		// Parse the JSON so it's available as input.body
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
		// System error — deny the request.
		slog.Error("opa evaluation error", "error", err, "client_ip", clientIP, "method", r.Method, "path", r.URL.Path)
		p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusInternalServerError, r.UserAgent(), fmt.Sprintf("policy evaluation error: %v", err))
		return
	}

	if !result.Allowed {
		p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusForbidden, r.UserAgent(), result.Reason)
		return
	}

	// ---- 5b. Optional isolation mediation ----
	if p.Isolation != nil {
		// Transform request: inject labels on creation, filters on list,
		// labels on build, filters on prune.
		p.Isolation.TransformRequest(r)

		// Verify that the target resource (if any) belongs to this
		// isolation context.  This makes an extra API call to Docker.
		if err := p.Isolation.CheckAccess(ctx, p.client, r.URL.Path); err != nil {
			slog.Warn("isolation check failed", "error", err, "path", r.URL.Path)
			p.logAndDeny(w, clientIP, r.Method, logPath, http.StatusForbidden, r.UserAgent(), err.Error())
			return
		}
	}

	// ---- 6. Forward to Docker daemon ----
	upstreamURL := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	upReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		slog.Error("create upstream request", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Copy headers.
	upReq.Header = r.Header.Clone()

	// Execute upstream.
	resp, err := p.client.Do(upReq)
	if err != nil {
		slog.Error("upstream request failed", "error", err, "method", r.Method, "path", r.URL.Path)
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Write status code.
	w.WriteHeader(resp.StatusCode)

	// Stream the body.
	io.Copy(w, resp.Body)

	// ---- 7. Log the request ----
	p.logAllowed(clientIP, r.Method, logPath, resp.StatusCode, r.UserAgent())
}

// buildOPAInput constructs the input map for OPA evaluation.
// body is kept as raw bytes initially; if it's valid JSON it will be
// unmarshalled later in the flow.
func buildOPAInput(r *http.Request, bodyBytes []byte, clientIP string) map[string]interface{} {
	input := map[string]interface{}{
		"method":    r.Method,
		"path":      r.URL.Path,
		"body":      string(bodyBytes), // will be replaced with parsed JSON if applicable
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
	// Check X-Forwarded-For first.
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// Then X-Real-Ip.
	if real := r.Header.Get("X-Real-Ip"); real != "" {
		return real
	}
	// Fall back to the remote address (strip port).
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
