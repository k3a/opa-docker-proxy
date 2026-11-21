package isolation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// BuildKit builds do not use POST /build: the client talks gRPC to the
// daemon over /grpc, and image names, labels and exporters travel inside the
// Solve request. This file applies the isolation rules to that request.
//
// It only deals with the decoded messages. Carrying them (HTTP upgrade,
// HTTP/2, gRPC framing) is up to the proxy package.

const (
	buildKitService = "/moby.buildkit.v1.Control/"
	bridgeService   = "/moby.buildkit.v1.frontend.LLBBridge/"

	// MethodSolve is the gRPC method whose first request message is a
	// SolveRequest.
	MethodSolve = buildKitService + "Solve"

	// MethodBridgeSolve is the call a client-side frontend makes to have the
	// daemon run a frontend. Its request is a frontend.SolveRequest.
	MethodBridgeSolve = bridgeService + "Solve"

	frontendDockerfile = "dockerfile.v0"
	frontendLabelAttr  = "label:"
)

// allowedBuildKitMethods are the control-service methods a client may call.
// The rest (DiskUsage, Prune, build history) read or change state shared by
// every isolation context.
var allowedBuildKitMethods = map[string]bool{
	MethodSolve:                     true,
	buildKitService + "Status":      true,
	buildKitService + "Session":     true,
	buildKitService + "Info":        true,
	buildKitService + "ListWorkers": true,

	// Current clients run the Dockerfile frontend themselves and call back
	// into the daemon through the LLB bridge. Container execution
	// (NewContainer, ExecProcess) is left out.
	bridgeService + "Ping":               true,
	bridgeService + "Solve":              true,
	bridgeService + "Return":             true,
	bridgeService + "Inputs":             true,
	bridgeService + "Evaluate":           true,
	bridgeService + "ReadFile":           true,
	bridgeService + "ReadDir":            true,
	bridgeService + "StatFile":           true,
	bridgeService + "ResolveImageConfig": true,
	bridgeService + "ResolveSourceMeta":  true,
	bridgeService + "Warn":               true,

	// Build tracing.
	"/opentelemetry.proto.collector.trace.v1.TraceService/Export": true,
}

// exporterTypes lists the exporters a Solve may use. The first group writes
// an image into the daemon's image store, the second only sends output to
// the client or discards it.
var exporterTypes = map[string]bool{
	"moby":      true,
	"image":     true,
	"local":     false,
	"tar":       false,
	"oci":       false,
	"docker":    false,
	"cacheonly": false,
}

// SolveRequest field numbers (moby/buildkit api/services/control/control.proto).
const (
	solveDefinition     protowire.Number = 2
	solveExporterType   protowire.Number = 3
	solveExporterAttrs  protowire.Number = 4
	solveFrontend       protowire.Number = 6
	solveFrontendAttrs  protowire.Number = 7
	solveEntitlements   protowire.Number = 9
	solveFrontendInputs protowire.Number = 10
	solveExporters      protowire.Number = 13
)

// BuildKit applies isolation to BuildKit gRPC calls.
type BuildKit struct {
	iso    *Isolation
	client *http.Client
}

// BuildKit returns the BuildKit guard of this isolation context. client talks
// to the Docker daemon directly, like the one passed to CheckAccess.
func (i *Isolation) BuildKit(client *http.Client) *BuildKit {
	return &BuildKit{iso: i, client: client}
}

// CheckMethod denies control-service methods that are not safe to expose.
func (b *BuildKit) CheckMethod(method string) error {
	if allowedBuildKitMethods[method] {
		return nil
	}

	return fmt.Errorf("access denied: BuildKit call %s is not allowed with isolation", method)
}

// Solve checks a SolveRequest and returns it rewritten so the resulting image
// carries the isolation label. The returned function must be called once the
// build has finished: it makes sure the image names the build wrote really
// point to labelled images.
func (b *BuildKit) Solve(ctx context.Context, msg []byte) ([]byte, func(), error) {
	fields, err := parseWire(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("access denied: malformed BuildKit solve request: %w", err)
	}

	out := make([]byte, 0, len(msg)+128)

	var (
		frontend  string
		exporters []exporter
		legacy    exporter
	)

	for _, f := range fields {
		switch f.num {
		case solveDefinition, solveFrontendInputs:
			// Pre-built build graphs and inputs have no Dockerfile to label.
			if len(f.val) > 0 || f.typ != protowire.BytesType {
				return nil, nil, errors.New("access denied: BuildKit solve with a prebuilt definition is not allowed with isolation")
			}
		case solveEntitlements:
			return nil, nil, errors.New("access denied: BuildKit entitlements are not allowed with isolation")
		case solveFrontend:
			frontend = string(f.val)
		case solveExporterType:
			legacy.typ = string(f.val)
		case solveExporterAttrs:
			k, v, err := parseMapEntry(f.val)
			if err != nil {
				return nil, nil, fmt.Errorf("access denied: malformed BuildKit exporter attrs: %w", err)
			}

			legacy.set(k, v)
		case solveExporters:
			e, err := parseExporter(f.val)
			if err != nil {
				return nil, nil, fmt.Errorf("access denied: malformed BuildKit exporter: %w", err)
			}

			exporters = append(exporters, e)
		case solveFrontendAttrs:
			k, _, err := parseMapEntry(f.val)
			if err != nil {
				return nil, nil, fmt.Errorf("access denied: malformed BuildKit frontend attrs: %w", err)
			}

			switch {
			case strings.EqualFold(k, frontendLabelAttr+LabelKey):
				// Client-supplied isolation label: dropped, ours is added below.
				continue
			case k == "source" || k == "cmdline":
				return nil, nil, errors.New("access denied: custom BuildKit frontends are not allowed with isolation")
			}
		}

		out = append(out, f.raw...)
	}

	// An empty frontend is the client-side frontend mode of current clients;
	// the Dockerfile frontend runs in the client then.
	if frontend != "" && frontend != frontendDockerfile {
		return nil, nil, fmt.Errorf("access denied: BuildKit frontend %q is not allowed with isolation (only %s)", frontend, frontendDockerfile)
	}

	if legacy.typ != "" || len(legacy.attrs) > 0 {
		exporters = append(exporters, legacy)
	}

	var names []string

	for _, e := range exporters {
		n, err := b.checkExporter(ctx, e)
		if err != nil {
			return nil, nil, err
		}

		names = append(names, n...)
	}

	// The Dockerfile frontend applies label:* attributes after the Dockerfile's
	// own LABEL instructions, so this one wins.
	out = protowire.AppendTag(out, solveFrontendAttrs, protowire.BytesType)
	out = protowire.AppendBytes(out, mapEntry(frontendLabelAttr+LabelKey, b.iso.Name))

	return out, func() { b.verify(names) }, nil
}

// frontend.SolveRequest field numbers (frontend/gateway/pb/gateway.proto).
const (
	bridgeFrontend    protowire.Number = 2
	bridgeFrontendOpt protowire.Number = 3
)

// BridgeSolve rewrites the first message of an LLBBridge Solve call so the
// Dockerfile frontend it starts labels the image. In client-side frontend
// mode this is where the frontend options are set, not in the Control Solve.
// A client that does not send the label gets caught by the check after the
// build.
func (b *BuildKit) BridgeSolve(msg []byte) ([]byte, error) {
	fields, err := parseWire(msg)
	if err != nil {
		return nil, fmt.Errorf("access denied: malformed BuildKit frontend request: %w", err)
	}

	out := make([]byte, 0, len(msg)+128)
	hasFrontend := false

	for _, f := range fields {
		switch f.num {
		case bridgeFrontend:
			hasFrontend = len(f.val) > 0
		case bridgeFrontendOpt:
			k, _, err := parseMapEntry(f.val)
			if err != nil {
				return nil, fmt.Errorf("access denied: malformed BuildKit frontend options: %w", err)
			}

			if strings.EqualFold(k, frontendLabelAttr+LabelKey) {
				continue
			}
		}

		out = append(out, f.raw...)
	}

	if hasFrontend {
		out = protowire.AppendTag(out, bridgeFrontendOpt, protowire.BytesType)
		out = protowire.AppendBytes(out, mapEntry(frontendLabelAttr+LabelKey, b.iso.Name))
	}

	return out, nil
}

// exporter is a decoded Exporter message.
type exporter struct {
	typ   string
	attrs map[string]string
}

func (e *exporter) set(k, v string) {
	if e.attrs == nil {
		e.attrs = map[string]string{}
	}

	e.attrs[k] = v
}

// checkExporter validates an exporter and returns the image names it writes.
func (b *BuildKit) checkExporter(ctx context.Context, e exporter) ([]string, error) {
	writesImage, known := exporterTypes[e.typ]
	if !known {
		return nil, fmt.Errorf("access denied: BuildKit exporter %q is not allowed with isolation", e.typ)
	}

	if !writesImage {
		return nil, nil
	}

	if p := e.attrs["push"]; p != "" && p != "false" {
		return nil, errors.New("access denied: pushing from a BuildKit build is not allowed with isolation")
	}

	var names []string

	for n := range strings.SplitSeq(e.attrs["name"], ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}

	for _, n := range names {
		if err := b.iso.checkImage(ctx, b.client, n, true); err != nil {
			return nil, fmt.Errorf("image name %q can not be written: %w", n, err)
		}
	}

	return names, nil
}

// verify untags names that do not point to an image of this context after a
// build. The label is injected as a frontend attribute, which only an honest
// frontend applies: a client running its own frontend, or a custom one named
// by a "# syntax=" line in the Dockerfile, is free to ignore it and to put
// any labels in the image config.
func (b *BuildKit) verify(names []string) {
	ctx := context.Background()

	for _, n := range names {
		st, err := b.iso.ownership(ctx, b.client, ResourceImage, n)
		if err != nil {
			slog.Warn("buildkit: verifying built image failed", "image", n, "error", err)

			continue
		}

		if st == owned || st == notFound {
			continue
		}

		slog.Warn("buildkit: built image lacks the isolation label, removing it", "image", n)

		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker/images/"+url.PathEscape(n), nil)
		if err != nil {
			continue
		}

		resp, err := b.client.Do(req)
		if err != nil {
			slog.Warn("buildkit: removing unlabelled image failed", "image", n, "error", err)

			continue
		}

		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close response body", "error", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Protobuf wire helpers
// ---------------------------------------------------------------------------

// wireField is one top-level field of an encoded message.
type wireField struct {
	num protowire.Number
	typ protowire.Type
	raw []byte // the whole encoded field, tag included
	val []byte // payload of a length-delimited field
}

// parseWire splits an encoded message into its fields without interpreting
// them, so unknown fields survive a rewrite untouched.
func parseWire(b []byte) ([]wireField, error) {
	var fields []wireField

	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}

		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			return nil, protowire.ParseError(m)
		}

		f := wireField{num: num, typ: typ, raw: b[:n+m]}
		if typ == protowire.BytesType {
			f.val, _ = protowire.ConsumeBytes(b[n:])
		}

		fields = append(fields, f)
		b = b[n+m:]
	}

	return fields, nil
}

// parseMapEntry decodes a map<string,string> entry.
func parseMapEntry(b []byte) (key, val string, err error) {
	fields, err := parseWire(b)
	if err != nil {
		return "", "", err
	}

	for _, f := range fields {
		switch f.num {
		case 1:
			key = string(f.val)
		case 2:
			val = string(f.val)
		}
	}

	return key, val, nil
}

// parseExporter decodes an Exporter message.
func parseExporter(b []byte) (exporter, error) {
	var e exporter

	fields, err := parseWire(b)
	if err != nil {
		return e, err
	}

	for _, f := range fields {
		switch f.num {
		case 1:
			e.typ = string(f.val)
		case 2:
			k, v, err := parseMapEntry(f.val)
			if err != nil {
				return e, err
			}

			e.set(k, v)
		}
	}

	return e, nil
}

// mapEntry encodes a map<string,string> entry.
func mapEntry(key, val string) []byte {
	b := protowire.AppendTag(nil, 1, protowire.BytesType)
	b = protowire.AppendString(b, key)
	b = protowire.AppendTag(b, 2, protowire.BytesType)

	return protowire.AppendString(b, val)
}
