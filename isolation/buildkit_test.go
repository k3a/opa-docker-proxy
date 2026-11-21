package isolation

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// solveReq encodes a SolveRequest from the parts the tests care about.
type solveReq struct {
	frontend  string
	attrs     [][2]string
	exporters []exporter
	extra     func([]byte) []byte
}

func (s solveReq) encode() []byte {
	var b []byte

	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendString(b, "session-id")
	b = protowire.AppendTag(b, solveFrontend, protowire.BytesType)
	b = protowire.AppendString(b, s.frontend)

	for _, a := range s.attrs {
		b = protowire.AppendTag(b, solveFrontendAttrs, protowire.BytesType)
		b = protowire.AppendBytes(b, mapEntry(a[0], a[1]))
	}

	for _, e := range s.exporters {
		var eb []byte

		eb = protowire.AppendTag(eb, 1, protowire.BytesType)
		eb = protowire.AppendString(eb, e.typ)

		for k, v := range e.attrs {
			eb = protowire.AppendTag(eb, 2, protowire.BytesType)
			eb = protowire.AppendBytes(eb, mapEntry(k, v))
		}

		b = protowire.AppendTag(b, solveExporters, protowire.BytesType)
		b = protowire.AppendBytes(b, eb)
	}

	if s.extra != nil {
		b = s.extra(b)
	}

	return b
}

func dockerfileSolve(name string) solveReq {
	return solveReq{
		frontend:  frontendDockerfile,
		attrs:     [][2]string{{"filename", "Dockerfile"}},
		exporters: []exporter{{typ: "moby", attrs: map[string]string{"name": name}}},
	}
}

func solve(t *testing.T, f *fake, req solveReq) ([]byte, func(), error) {
	t.Helper()

	iso, _ := New(testName, ModeFull)

	return iso.BuildKit(f.client(t)).Solve(context.Background(), req.encode())
}

func frontendAttrsOf(t *testing.T, msg []byte) map[string]string {
	t.Helper()

	fields, err := parseWire(msg)
	if err != nil {
		t.Fatal(err)
	}

	attrs := map[string]string{}

	for _, f := range fields {
		if f.num == solveFrontendAttrs {
			k, v, _ := parseMapEntry(f.val)
			attrs[k] = v
		}
	}

	return attrs
}

func TestSolveInjectsLabel(t *testing.T) {
	out, _, err := solve(t, newWorld(), dockerfileSolve("brandnew:1"))
	if err != nil {
		t.Fatal(err)
	}

	attrs := frontendAttrsOf(t, out)
	if attrs[frontendLabelAttr+LabelKey] != testName || attrs["filename"] != "Dockerfile" {
		t.Errorf("frontend attrs %v", attrs)
	}

	// unrelated fields survive
	if !strings.Contains(string(out), "session-id") {
		t.Error("session field lost")
	}
}

func TestSolveReplacesClientLabel(t *testing.T) {
	req := dockerfileSolve("brandnew")
	req.attrs = append(req.attrs, [2]string{frontendLabelAttr + LabelKey, "victim"}, [2]string{"label:keep", "1"})

	out, _, err := solve(t, newWorld(), req)
	if err != nil {
		t.Fatal(err)
	}

	attrs := frontendAttrsOf(t, out)
	if attrs[frontendLabelAttr+LabelKey] != testName || attrs["label:keep"] != "1" || strings.Contains(string(out), "victim") {
		t.Errorf("frontend attrs %v", attrs)
	}
}

func TestSolveDenied(t *testing.T) {
	cases := map[string]solveReq{
		"shared name":    dockerfileSolve("alpine:3.19"),
		"foreign name":   dockerfileSolve("otherimg"),
		"second name":    dockerfileSolve("brandnew,otherimg"),
		"gateway":        {frontend: "gateway.v0", exporters: dockerfileSolve("x").exporters},
		"no frontend":    {exporters: dockerfileSolve("x").exporters},
		"push":           {frontend: frontendDockerfile, exporters: []exporter{{typ: "image", attrs: map[string]string{"name": "x", "push": "true"}}}},
		"unknown export": {frontend: frontendDockerfile, exporters: []exporter{{typ: "registry"}}},
		"syntax source": {frontend: frontendDockerfile, attrs: [][2]string{{"source", "evil/frontend"}},
			exporters: dockerfileSolve("x").exporters},
		"cmdline": {frontend: frontendDockerfile, attrs: [][2]string{{"cmdline", "evil/frontend"}},
			exporters: dockerfileSolve("x").exporters},
		"definition": {frontend: frontendDockerfile, exporters: dockerfileSolve("x").exporters, extra: func(b []byte) []byte {
			return protowire.AppendString(protowire.AppendTag(b, solveDefinition, protowire.BytesType), "llb")
		}},
		"entitlement": {frontend: frontendDockerfile, exporters: dockerfileSolve("x").exporters, extra: func(b []byte) []byte {
			return protowire.AppendString(protowire.AppendTag(b, solveEntitlements, protowire.BytesType), "security.insecure")
		}},
		"legacy exporter to shared name": {frontend: frontendDockerfile, extra: func(b []byte) []byte {
			b = protowire.AppendString(protowire.AppendTag(b, solveExporterType, protowire.BytesType), "moby")

			return protowire.AppendBytes(protowire.AppendTag(b, solveExporterAttrs, protowire.BytesType), mapEntry("name", "alpine:3.19"))
		}},
	}

	for name, req := range cases {
		if _, _, err := solve(t, newWorld(), req); err == nil {
			t.Errorf("%s: allowed", name)
		}
	}

	iso, _ := New(testName, ModeFull)
	if _, _, err := iso.BuildKit(newWorld().client(t)).Solve(context.Background(), []byte{0xff, 0xff}); err == nil {
		t.Error("malformed request allowed")
	}
}

func TestSolveAllowed(t *testing.T) {
	cases := map[string]solveReq{
		"own name":  dockerfileSolve("myimg:v2"),
		"new names": dockerfileSolve("a:1, b:2"),
		"no export": {frontend: frontendDockerfile},
		"tar out":   {frontend: frontendDockerfile, exporters: []exporter{{typ: "tar"}}},
	}

	for name, req := range cases {
		if _, _, err := solve(t, newWorld(), req); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBuildKitMethods(t *testing.T) {
	iso, _ := New(testName, ModeFull)
	b := iso.BuildKit(newWorld().client(t))

	for _, m := range []string{MethodSolve, buildKitService + "Status", buildKitService + "Session"} {
		if err := b.CheckMethod(m); err != nil {
			t.Errorf("%s: %v", m, err)
		}
	}

	for _, m := range []string{buildKitService + "Prune", buildKitService + "DiskUsage", buildKitService + "ListenBuildHistory", "/other.Service/Call"} {
		if b.CheckMethod(m) == nil {
			t.Errorf("%s allowed", m)
		}
	}
}

func TestSolveVerifyUntagsUnlabelled(t *testing.T) {
	f := newWorld()

	var deleted []string

	iso, _ := New(testName, ModeFull)
	client := f.client(t)
	inner := client.Transport
	client.Transport = roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, r.URL.Path)
		}

		return inner.RoundTrip(r)
	})

	// built names: one labelled, one not (a custom frontend ignored the label)
	f.docs["/images/good:1/json"] = container(mine)
	f.docs["/images/bad:1/json"] = container(nil)

	b := iso.BuildKit(client)
	b.verify([]string{"good:1", "bad:1", "missing:1"})

	if len(deleted) != 1 || deleted[0] != "/images/bad:1" {
		t.Errorf("deleted %v", deleted)
	}
}
