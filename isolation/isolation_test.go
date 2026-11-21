package isolation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testName = "dev"

// fakeDocker answers inspect calls from a table: path -> labels.
// Paths not in the table are 404.
func fakeDocker(t *testing.T, labels map[string]map[string]any) *http.Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l, ok := labels[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)

			return
		}

		var resp map[string]any

		switch {
		case strings.HasPrefix(r.URL.Path, "/containers/"):
			resp = map[string]any{"Config": map[string]any{"Labels": l}}
		case strings.HasPrefix(r.URL.Path, "/exec/"):
			resp = l // {"ContainerID": "..."}
		default:
			resp = map[string]any{"Labels": l}
		}

		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL)

	return &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme, r.URL.Host = "http", u.Host

		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var mine = map[string]any{LabelKey: testName}
var other = map[string]any{LabelKey: "someone-else"}

// world: what exists on the fake daemon.
func world(t *testing.T) *http.Client {
	return fakeDocker(t, map[string]map[string]any{
		"/containers/mine/json":  mine,
		"/containers/other/json": other,
		"/containers/bare/json":  {},
		"/volumes/myvol":         mine,
		"/volumes/othervol":      other,
		"/networks/mynet":        mine,
		"/networks/othernet":     other,
		"/exec/myexec/json":      {"ContainerID": "mine"},
		"/exec/otherexec/json":   {"ContainerID": "other"},
	})
}

func newReq(method, path, body string) *http.Request {
	r, _ := http.NewRequest(method, "http://proxy"+path, strings.NewReader(body))

	return r
}

func check(t *testing.T, mode Mode, r *http.Request) error {
	t.Helper()

	iso, err := New(testName, mode)
	if err != nil {
		t.Fatal(err)
	}

	return iso.CheckAccess(context.Background(), world(t), r)
}

func TestCheckTarget(t *testing.T) {
	tests := []struct {
		method, path string
		wantErr      bool
	}{
		{"POST", "/containers/mine/start", false},
		{"POST", "/v1.44/containers/mine/stop", false},
		{"DELETE", "/containers/mine", false},
		{"POST", "/containers/other/start", true},
		{"DELETE", "/containers/other", true},
		{"POST", "/containers/bare/kill", true},
		{"POST", "/containers/missing/start", true},
		{"POST", "/containers/mine/exec", false},
		{"POST", "/containers/other/exec", true},
		{"POST", "/exec/myexec/start", false},
		{"POST", "/exec/otherexec/start", true},
		{"DELETE", "/volumes/myvol", false},
		{"DELETE", "/volumes/othervol", true},
		{"DELETE", "/networks/othernet", true},
		{"GET", "/containers/other/json", true}, // full mode hides reads
		{"GET", "/containers/json", false},      // list: filtered, not checked
		{"GET", "/images/alpine/json", false},   // images are shared
		{"DELETE", "/images/alpine", false},     // ... and not checked
		{"POST", "/containers/create", false},   // no body → nothing to check
		{"POST", "/containers/prune", false},    // scoped by filter, not checked
		{"GET", "/_ping", false},
	}

	for _, tc := range tests {
		err := check(t, ModeFull, newReq(tc.method, tc.path, ""))
		if (err != nil) != tc.wantErr {
			t.Errorf("full %s %s: err=%v wantErr=%v", tc.method, tc.path, err, tc.wantErr)
		}
	}
}

func TestWritesModeLeavesReadsAlone(t *testing.T) {
	if err := check(t, ModeWrites, newReq("GET", "/containers/other/json", "")); err != nil {
		t.Errorf("read of foreign container denied in writes mode: %v", err)
	}

	if err := check(t, ModeWrites, newReq("HEAD", "/containers/other/archive", "")); err != nil {
		t.Errorf("HEAD denied in writes mode: %v", err)
	}

	for _, p := range []string{"/containers/other/start", "/containers/other/exec"} {
		if err := check(t, ModeWrites, newReq("POST", p, "")); err == nil {
			t.Errorf("write %s on foreign container allowed in writes mode", p)
		}
	}

	if err := check(t, ModeWrites, newReq("DELETE", "/containers/other", "")); err == nil {
		t.Error("delete of foreign container allowed in writes mode")
	}

	// websocket attach is a GET that can write.
	if err := check(t, ModeWrites, newReq("GET", "/containers/other/attach/ws", "")); err == nil {
		t.Error("attach/ws on foreign container allowed in writes mode")
	}

	if err := check(t, ModeWrites, newReq("POST", "/containers/mine/start", "")); err != nil {
		t.Errorf("own container denied: %v", err)
	}
}

func TestCreateReferences(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"plain", `{"Image":"alpine"}`, false},
		{"builtin network", `{"HostConfig":{"NetworkMode":"bridge"}}`, false},
		{"own network", `{"HostConfig":{"NetworkMode":"mynet"}}`, false},
		{"foreign network", `{"HostConfig":{"NetworkMode":"othernet"}}`, true},
		{"foreign endpoint network", `{"NetworkingConfig":{"EndpointsConfig":{"othernet":{}}}}`, true},
		{"own endpoint network", `{"NetworkingConfig":{"EndpointsConfig":{"mynet":{}}}}`, false},
		{"join foreign netns", `{"HostConfig":{"NetworkMode":"container:other"}}`, true},
		{"join own netns", `{"HostConfig":{"NetworkMode":"container:mine"}}`, false},
		{"foreign pidmode", `{"HostConfig":{"PidMode":"container:other"}}`, true},
		{"volumes from foreign", `{"HostConfig":{"VolumesFrom":["other:ro"]}}`, true},
		{"volumes from own", `{"HostConfig":{"VolumesFrom":["mine"]}}`, false},
		{"link foreign", `{"HostConfig":{"Links":["other:db"]}}`, true},
		{"foreign named volume bind", `{"HostConfig":{"Binds":["othervol:/x"]}}`, true},
		{"own named volume bind", `{"HostConfig":{"Binds":["myvol:/x:ro"]}}`, false},
		{"new named volume bind", `{"HostConfig":{"Binds":["brandnew:/x"]}}`, false},
		{"host path bind not a reference", `{"HostConfig":{"Binds":["/dev/sda:/x"]}}`, false},
		{"foreign volume mount", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"othervol","Target":"/x"}]}}`, true},
		{"own volume mount", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"myvol","Target":"/x"}]}}`, false},
		{"bind mount source is not a volume ref", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"othervol","Target":"/x"}]}}`, false},
		// Docker decodes keys case-insensitively.
		{"foreign network, odd case", `{"hostconfig":{"networkmode":"othernet"}}`, true},
		{"volumes from, odd case", `{"HOSTCONFIG":{"volumesfrom":["other"]}}`, true},
		{"not json", `nope`, false},
	}

	for _, tc := range tests {
		for _, mode := range []Mode{ModeFull, ModeWrites} {
			err := check(t, mode, newReq("POST", "/containers/create", tc.body))
			if (err != nil) != tc.wantErr {
				t.Errorf("%s (%s): err=%v wantErr=%v", tc.name, mode, err, tc.wantErr)
			}
		}
	}
}

func TestReferenceIDCannotEscapeInspectPath(t *testing.T) {
	// Without escaping, this would inspect /containers/x/../../containers/mine/json
	// (an owned container) instead of the named, foreign one.
	body := `{"HostConfig":{"VolumesFrom":["other/../../mine"]}}`
	if err := check(t, ModeFull, newReq("POST", "/containers/create", body)); err != nil {
		// 404 for the escaped name = notFound = left to the daemon: allowed.
		t.Fatalf("unexpected: %v", err)
	}
}

func TestNetworkConnectChecksContainer(t *testing.T) {
	ok := newReq("POST", "/networks/mynet/connect", `{"Container":"mine"}`)
	if err := check(t, ModeFull, ok); err != nil {
		t.Errorf("own container to own network: %v", err)
	}

	bad := newReq("POST", "/networks/mynet/connect", `{"Container":"other"}`)
	if err := check(t, ModeFull, bad); err == nil {
		t.Error("foreign container connected to own network")
	}

	bad = newReq("POST", "/networks/othernet/connect", `{"Container":"mine"}`)
	if err := check(t, ModeFull, bad); err == nil {
		t.Error("own container connected to foreign network")
	}
}

func TestCheckReferencesRestoresBody(t *testing.T) {
	r := newReq("POST", "/containers/create", `{"Image":"alpine"}`)
	if err := check(t, ModeFull, r); err != nil {
		t.Fatal(err)
	}

	b, _ := io.ReadAll(r.Body)
	if string(b) != `{"Image":"alpine"}` {
		t.Errorf("body not restored: %q", b)
	}
}

func transformed(t *testing.T, mode Mode, r *http.Request) *http.Request {
	t.Helper()

	iso, _ := New(testName, mode)
	iso.TransformRequest(r)

	return r
}

func TestTransformCreateInjectsLabels(t *testing.T) {
	body := `{"Image":"alpine","labels":{"` + LabelKey + `":"victim","keep":"1"},"Labels":{"a":"b"},` +
		`"HostConfig":{"Mounts":[{"Type":"volume","Source":"v","Target":"/v"},{"Type":"bind","Source":"/dev/x","Target":"/x"}]}}`
	r := transformed(t, ModeFull, newReq("POST", "/containers/create", body))

	b, _ := io.ReadAll(r.Body)

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	labels := got["Labels"].(map[string]any)
	if labels[LabelKey] != testName || labels["keep"] != "1" || labels["a"] != "b" {
		t.Errorf("labels = %v", labels)
	}

	if _, dup := got["labels"]; dup {
		t.Error("case-variant labels key survived and could override the isolation label")
	}

	mounts := got["HostConfig"].(map[string]any)["Mounts"].([]any)

	vol := mounts[0].(map[string]any)["VolumeOptions"].(map[string]any)["Labels"].(map[string]any)
	if vol[LabelKey] != testName {
		t.Errorf("implicit volume not labelled: %v", vol)
	}

	if _, ok := mounts[1].(map[string]any)["VolumeOptions"]; ok {
		t.Error("bind mount got VolumeOptions")
	}

	if r.ContentLength != int64(len(b)) {
		t.Errorf("ContentLength %d != body %d", r.ContentLength, len(b))
	}
}

func TestTransformFilters(t *testing.T) {
	for _, p := range []string{"/containers/json", "/volumes", "/networks", "/events", "/v1.44/containers/json", "/containers/prune"} {
		r := transformed(t, ModeFull, newReq("GET", p, ""))
		if !strings.Contains(r.URL.RawQuery, "filters=") || !strings.Contains(r.URL.Query().Get("filters"), LabelKey+"="+testName) {
			t.Errorf("%s: filters not injected: %q", p, r.URL.RawQuery)
		}
	}

	// images are shared: listing is not filtered ...
	r := transformed(t, ModeFull, newReq("GET", "/images/json", ""))
	if r.URL.RawQuery != "" {
		t.Errorf("image list filtered: %q", r.URL.RawQuery)
	}
}

func TestTransformWritesModeOnlyScopesChanges(t *testing.T) {
	r := transformed(t, ModeWrites, newReq("GET", "/containers/json", ""))
	if r.URL.RawQuery != "" {
		t.Errorf("list filtered in writes mode: %q", r.URL.RawQuery)
	}

	r = transformed(t, ModeWrites, newReq("POST", "/containers/prune", ""))
	if !strings.Contains(r.URL.Query().Get("filters"), LabelKey) {
		t.Errorf("prune not scoped in writes mode: %q", r.URL.RawQuery)
	}

	r = transformed(t, ModeWrites, newReq("POST", "/containers/create", `{}`))
	b, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(b), LabelKey) {
		t.Errorf("create not labelled in writes mode: %s", b)
	}
}

func TestNewValidatesMode(t *testing.T) {
	if _, err := New("x", "bogus"); err == nil {
		t.Error("bogus mode accepted")
	}

	i, err := New("x", "")
	if err != nil || i.Mode != ModeFull {
		t.Errorf("default mode = %v, %v", i, err)
	}
}
