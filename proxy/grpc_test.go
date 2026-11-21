package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"golang.org/x/net/http2"

	"github.com/k3a/opa-docker-proxy/config"
	"github.com/k3a/opa-docker-proxy/isolation"
)

type fakeGuard struct{ solved chan struct{} }

func (g fakeGuard) CheckMethod(m string) error {
	if m == "/svc/Denied" {
		return errors.New("access denied: nope")
	}

	return nil
}

func (g fakeGuard) BridgeSolve(msg []byte) ([]byte, error) {
	return append([]byte("bridged:"), msg...), nil
}

func (g fakeGuard) Solve(_ context.Context, msg []byte) ([]byte, func(), error) {
	if string(msg) == "bad" {
		return nil, nil, errors.New("access denied: bad solve")
	}

	return append([]byte("guarded:"), msg...), func() { close(g.solved) }, nil
}

// upgradeServer plays the Docker daemon: it accepts the /grpc upgrade and
// serves HTTP/2 whose handler echoes the request messages back.
func upgradeServer(t *testing.T) string {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "docker.sock")

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			go func() {
				br := bufio.NewReader(c)

				req, err := http.ReadRequest(br)
				if err != nil || req.URL.Path != "/grpc" || req.Header.Get("Upgrade") != "h2c" || req.Header.Get("X-Marker") != "1" {
					_ = c.Close()

					return
				}

				_, _ = io.WriteString(c, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")

				(&http2.Server{}).ServeConn(&bufferedConn{Conn: c, r: br}, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(body)
					w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
				})})
			}()
		}
	}()

	return sock
}

func TestGRPCBridge(t *testing.T) {
	guard := fakeGuard{solved: make(chan struct{})}
	p := &Proxy{config: config.Config{DockerSocket: upgradeServer(t)}}

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.serveGRPC(w, r, guard) }))
	defer front.Close()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, _ = io.WriteString(conn, "POST /grpc HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nX-Marker: 1\r\n\r\n")

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}

	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(&bufferedConn{Conn: conn, r: br})
	if err != nil {
		t.Fatal(err)
	}

	call := func(method string, msg []byte) (*http.Response, []byte) {
		req, _ := http.NewRequest(http.MethodPost, "http://docker"+method, bytes.NewReader(frameGRPC(msg)))
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("Te", "trailers")

		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}

		body, _ := io.ReadAll(resp.Body)

		return resp, body
	}

	// ordinary call: passed through untouched, trailers relayed
	resp, body := call("/svc/Echo", []byte("hello"))
	if !bytes.Equal(body, frameGRPC([]byte("hello"))) || resp.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("echo: body %q trailer %v", body, resp.Trailer)
	}

	// denied method never reaches the daemon
	resp, _ = call("/svc/Denied", []byte("x"))
	if resp.Header.Get("Grpc-Status") != "7" {
		t.Errorf("denied: %v", resp.Header)
	}

	// solve: first message rewritten, done callback run afterwards
	_, body = call(isolation.MethodSolve, []byte("req"))
	if !bytes.Equal(body, frameGRPC([]byte("guarded:req"))) {
		t.Errorf("solve body %q", body)
	}

	<-guard.solved

	// bridge solve: rewritten too
	_, body = call(isolation.MethodBridgeSolve, []byte("req"))
	if !bytes.Equal(body, frameGRPC([]byte("bridged:req"))) {
		t.Errorf("bridge solve body %q", body)
	}

	resp, _ = call(isolation.MethodSolve, []byte("bad"))
	if resp.Header.Get("Grpc-Status") != "7" {
		t.Errorf("bad solve: %v", resp.Header)
	}
}
