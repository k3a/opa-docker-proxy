package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/net/http2"

	"github.com/k3a/opa-docker-proxy/isolation"
)

// BuildKit clients talk gRPC to the daemon over POST /grpc, which is upgraded
// to cleartext HTTP/2 ("h2c"). The bridge below terminates that HTTP/2
// connection and re-originates every call on a second upgraded connection to
// the daemon, so a guard can look at (and rewrite) calls on the way through.
// Nothing else about the calls changes: headers, streaming and trailers are
// passed on as they are.

// grpcGuard decides what BuildKit calls may do.
type grpcGuard interface {
	// CheckMethod returns an error for methods that are not allowed.
	CheckMethod(method string) error
	// Solve checks the first message of a Solve call. It returns the message
	// to forward and a function to call once the call has finished.
	Solve(ctx context.Context, msg []byte) ([]byte, func(), error)
}

var _ grpcGuard = (*isolation.BuildKit)(nil)

const (
	grpcDenied      = "7"  // PERMISSION_DENIED
	grpcUnavailable = "14" // UNAVAILABLE

	// maxSolveMessage bounds the Solve request that is buffered for rewriting.
	maxSolveMessage = 16 << 20
)

func isGRPCPath(cleaned string) bool { return cleaned == "/grpc" }

// serveGRPC upgrades the client connection, opens one to the daemon and
// bridges them until either side closes.
func (p *Proxy) serveGRPC(w http.ResponseWriter, r *http.Request, guard grpcGuard) {
	upstream, err := p.dialGRPC(r)
	if err != nil {
		slog.Error("grpc: connecting to docker", "error", err)
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)

		return
	}
	defer closeQuietly(upstream)

	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(upstream)
	if err != nil {
		slog.Error("grpc: http2 to docker", "error", err)
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)

		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection can not be upgraded", http.StatusInternalServerError)

		return
	}

	client, brw, err := hj.Hijack()
	if err != nil {
		slog.Error("grpc: hijack", "error", err)

		return
	}
	defer closeQuietly(client)

	if _, err := io.WriteString(client, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"); err != nil {
		return
	}

	var clientConn net.Conn = client
	if brw.Reader.Buffered() > 0 {
		clientConn = &bufferedConn{Conn: client, r: brw.Reader}
	}

	b := &grpcBridge{cc: cc, guard: guard}

	(&http2.Server{}).ServeConn(clientConn, &http2.ServeConnOpts{
		Context: r.Context(),
		Handler: http.HandlerFunc(b.serve),
	})
}

// dialGRPC opens a connection to the daemon and performs the /grpc upgrade
// with the headers of the client's own upgrade request.
func (p *Proxy) dialGRPC(r *http.Request) (net.Conn, error) {
	conn, err := net.Dial("unix", p.config.DockerSocket)
	if err != nil {
		return nil, err
	}

	req := r.Clone(r.Context())
	req.URL.Scheme, req.URL.Host = "http", "docker"
	req.Host, req.RequestURI, req.Body, req.ContentLength = "docker", "", nil, 0

	if err := req.Write(conn); err != nil {
		closeQuietly(conn)

		return nil, err
	}

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		closeQuietly(conn)

		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		closeQuietly(conn)

		return nil, fmt.Errorf("docker answered %s to /grpc", resp.Status)
	}

	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn reads through r first, which may hold bytes already taken off
// the connection.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func closeQuietly(c io.Closer) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Debug("close failed", "error", err)
	}
}

// grpcBridge forwards the calls made over one upgraded connection.
type grpcBridge struct {
	cc    *http2.ClientConn
	guard grpcGuard
}

func (b *grpcBridge) serve(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Path

	if err := b.guard.CheckMethod(method); err != nil {
		slog.Warn("grpc call denied", "method", method, "error", err)
		grpcFail(w, grpcDenied, err.Error())

		return
	}

	body := r.Body

	var done func()

	if method == isolation.MethodSolve {
		msg, rest, err := readGRPCMessage(r.Body)
		if err != nil {
			grpcFail(w, grpcDenied, "access denied: "+err.Error())

			return
		}

		msg, done, err = b.guard.Solve(r.Context(), msg)
		if err != nil {
			slog.Warn("grpc call denied", "method", method, "error", err)
			grpcFail(w, grpcDenied, err.Error())

			return
		}

		body = io.NopCloser(io.MultiReader(bytes.NewReader(frameGRPC(msg)), rest))
	}

	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host = "http", "docker"
	out.Host, out.RequestURI = "docker", ""
	out.Body, out.ContentLength = body, -1

	resp, err := b.cc.RoundTrip(out)
	if err != nil {
		slog.Error("grpc: upstream call failed", "method", method, "error", err)
		grpcFail(w, grpcUnavailable, "upstream error: "+err.Error())

		return
	}
	defer closeQuietly(resp.Body)

	if done != nil {
		// Runs after the response, trailers included, has been relayed.
		defer done()
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)
	relay(w, resp.Body)

	// gRPC reports its status in the trailers.
	for k, v := range resp.Trailer {
		w.Header()[http.TrailerPrefix+k] = v
	}
}

// relay copies src to w, flushing after every chunk so streamed responses
// (build progress) reach the client without delay.
func relay(w http.ResponseWriter, src io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			_, werr := w.Write(buf[:n])
			ferr := rc.Flush()

			if werr != nil || ferr != nil {
				return
			}
		}

		if err != nil {
			return
		}
	}
}

// grpcFail ends a call with a gRPC status, as a trailers-only response.
func grpcFail(w http.ResponseWriter, code, msg string) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Grpc-Status", code)
	h.Set("Grpc-Message", url.PathEscape(msg))
	w.WriteHeader(http.StatusOK)
}

// readGRPCMessage reads the first length-prefixed message of a call body and
// returns it together with the unread remainder of the body.
func readGRPCMessage(body io.Reader) (msg []byte, rest io.Reader, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(body, hdr[:]); err != nil {
		return nil, nil, fmt.Errorf("reading call: %w", err)
	}

	if hdr[0] != 0 {
		return nil, nil, errors.New("compressed gRPC messages are not supported")
	}

	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxSolveMessage {
		return nil, nil, errors.New("gRPC message too large: " + strconv.FormatUint(uint64(n), 10))
	}

	msg = make([]byte, n)
	if _, err := io.ReadFull(body, msg); err != nil {
		return nil, nil, fmt.Errorf("reading call: %w", err)
	}

	return msg, body, nil
}

// frameGRPC adds the gRPC message prefix.
func frameGRPC(msg []byte) []byte {
	out := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(out[1:], uint32(len(msg)))

	return append(out, msg...)
}
