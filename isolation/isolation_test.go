package isolation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const testName = "dev"

// fake is a minimal Docker daemon: inspect answers come from docs (escaped
// path -> JSON document); POST /volumes/create adds a volume document.
type fake struct {
	docs    map[string]map[string]any
	created []string
}

func (f *fake) client(t *testing.T) *http.Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/volumes/create" {
			var in struct {
				Name   string
				Labels map[string]any
			}

			_ = json.NewDecoder(r.Body).Decode(&in)

			if _, exists := f.docs["/volumes/"+in.Name]; !exists {
				f.docs["/volumes/"+in.Name] = map[string]any{"Labels": in.Labels}
				f.created = append(f.created, in.Name)
			}

			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))

			return
		}

		doc, ok := f.docs[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)

			return
		}

		_ = json.NewEncoder(w).Encode(doc)
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

var (
	mine  = map[string]any{LabelKey: testName}
	other = map[string]any{LabelKey: "someone-else"}
)

func container(l map[string]any) map[string]any {
	return map[string]any{"Config": map[string]any{"Labels": l}}
}

func labelled(l map[string]any) map[string]any { return map[string]any{"Labels": l} }

func newWorld() *fake {
	return &fake{docs: map[string]map[string]any{
		"/containers/mine/json":  container(mine),
		"/containers/other/json": container(other),
		"/containers/bare/json":  container(map[string]any{}),
		"/volumes/myvol":         labelled(mine),
		"/volumes/othervol":      labelled(other),
		"/networks/mynet":        labelled(mine),
		"/networks/othernet":     labelled(other),
		"/exec/myexec/json":      {"ContainerID": "mine"},
		"/exec/otherexec/json":   {"ContainerID": "other"},
		// images: ours, foreign, shared (unlabelled), shared with VOLUME
		"/images/myimg/json":          container(mine),
		"/images/otherimg/json":       container(other),
		"/images/library/alpine/json": container(nil),
		"/images/alpine:3.19/json":    container(nil),
		"/images/withvol/json":        {"Config": map[string]any{"Volumes": map[string]any{"/var/lib/data": map[string]any{}}}},
	}}
}

func newReq(method, path, body string) *http.Request {
	r, _ := http.NewRequest(method, "http://proxy"+path, strings.NewReader(body))

	return r
}

func check(t *testing.T, mode Mode, r *http.Request) error {
	t.Helper()

	return checkWith(t, newWorld(), mode, r)
}

func checkWith(t *testing.T, f *fake, mode Mode, r *http.Request) error {
	t.Helper()

	iso, err := New(testName, mode)
	if err != nil {
		t.Fatal(err)
	}

	return iso.CheckAccess(context.Background(), f.client(t), r)
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
		{"image: own", `{"Image":"myimg"}`, false},
		{"image: shared", `{"Image":"alpine:3.19"}`, false},
		{"image: foreign", `{"Image":"otherimg"}`, true},
		{"image: foreign, odd case", `{"IMAGE":"otherimg"}`, true},
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

func TestCommit(t *testing.T) {
	// own container: allowed, label injected (also when the client sends none)
	iso, _ := New(testName, ModeFull)

	r := newReq("POST", "/commit?container=mine&repo=x", "")
	iso.TransformRequest(r)

	b, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(b), `"`+LabelKey+`":"`+testName+`"`) || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("empty commit body not labelled: %s (%s)", b, r.Header.Get("Content-Type"))
	}

	if r.ContentLength != int64(len(b)) {
		t.Errorf("ContentLength %d != %d", r.ContentLength, len(b))
	}

	// spoofed label is overwritten
	r = newReq("POST", "/commit?container=mine", `{"Labels":{"`+LabelKey+`":"victim"}}`)
	iso.TransformRequest(r)

	b, _ = io.ReadAll(r.Body)
	if strings.Contains(string(b), "victim") {
		t.Errorf("spoofed label kept: %s", b)
	}

	if err := check(t, ModeFull, newReq("POST", "/commit?container=mine", "")); err != nil {
		t.Errorf("commit of own container: %v", err)
	}

	for _, mode := range []Mode{ModeFull, ModeWrites} {
		if err := check(t, mode, newReq("POST", "/commit?container=other", "")); err == nil {
			t.Errorf("commit of foreign container allowed (%s)", mode)
		}
	}
}

func TestImagesGetNames(t *testing.T) {
	if err := check(t, ModeFull, newReq("GET", "/images/get?names=myimg&names=alpine:3.19", "")); err != nil {
		t.Errorf("own+shared export: %v", err)
	}

	if err := check(t, ModeFull, newReq("GET", "/images/get?names=myimg&names=otherimg", "")); err == nil {
		t.Error("export of foreign image allowed")
	}
}

func TestPrecreateNamedVolumes(t *testing.T) {
	f := newWorld()

	body := `{"HostConfig":{"Binds":["brandnew:/x","myvol:/y"],"Mounts":[{"Type":"volume","Source":"viamount","Target":"/z"}]}}`
	if err := checkWith(t, f, ModeFull, newReq("POST", "/containers/create", body)); err != nil {
		t.Fatal(err)
	}

	slices.Sort(f.created)

	if !slices.Equal(f.created, []string{"brandnew", "viamount"}) {
		t.Errorf("created = %v", f.created)
	}

	for _, n := range f.created {
		if f.docs["/volumes/"+n]["Labels"].(map[string]any)[LabelKey] != testName {
			t.Errorf("volume %s not labelled", n)
		}
	}

	// A foreign volume is never created over or used.
	f = newWorld()
	if err := checkWith(t, f, ModeFull, newReq("POST", "/containers/create", `{"HostConfig":{"Binds":["othervol:/x"]}}`)); err == nil || len(f.created) != 0 {
		t.Errorf("foreign volume: err=%v created=%v", err, f.created)
	}

	// Non-default driver: not pre-created (would pin the wrong driver).
	f = newWorld()

	driver := `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"nfsvol","Target":"/z","VolumeOptions":{"DriverConfig":{"Name":"nfs"}}}]}}`
	if err := checkWith(t, f, ModeFull, newReq("POST", "/containers/create", driver)); err != nil || len(f.created) != 0 {
		t.Errorf("driver volume: err=%v created=%v", err, f.created)
	}
}

func rewritten(t *testing.T, body string) map[string]any {
	t.Helper()

	r := newReq("POST", "/containers/create", body)
	if err := checkWith(t, newWorld(), ModeFull, r); err != nil {
		t.Fatal(err)
	}

	b, _ := io.ReadAll(r.Body)

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	if r.ContentLength != int64(len(b)) {
		t.Errorf("ContentLength %d != %d", r.ContentLength, len(b))
	}

	return got
}

// anonTargets returns the Targets of labelled anonymous volume mounts.
func anonTargets(t *testing.T, got map[string]any) []string {
	t.Helper()

	hc, _ := got["HostConfig"].(map[string]any)
	mounts, _ := hc["Mounts"].([]any)

	var out []string

	for _, m := range mounts {
		mm := m.(map[string]any)
		if mm["Type"] != "volume" || mm["Source"] != nil {
			continue
		}

		l := mm["VolumeOptions"].(map[string]any)["Labels"].(map[string]any)
		if l[LabelKey] != testName {
			t.Errorf("anonymous mount %v not labelled", mm)
		}

		out = append(out, mm["Target"].(string))
	}

	slices.Sort(out)

	return out
}

func TestAnonymousVolumesAreLabelled(t *testing.T) {
	// single-element Binds
	got := rewritten(t, `{"Image":"alpine:3.19","HostConfig":{"Binds":["/data","myvol:/keep:ro"]}}`)
	if tg := anonTargets(t, got); !slices.Equal(tg, []string{"/data"}) {
		t.Errorf("binds: %v", tg)
	}

	binds := got["HostConfig"].(map[string]any)["Binds"].([]any)
	if len(binds) != 1 || binds[0] != "myvol:/keep:ro" {
		t.Errorf("Binds after rewrite = %v", binds)
	}

	// config "Volumes"
	got = rewritten(t, `{"Image":"alpine:3.19","Volumes":{"/cache":{}}}`)
	if tg := anonTargets(t, got); !slices.Equal(tg, []string{"/cache"}) {
		t.Errorf("Volumes: %v", tg)
	}

	// volumes declared by the image (Dockerfile VOLUME)
	got = rewritten(t, `{"Image":"withvol"}`)
	if tg := anonTargets(t, got); !slices.Equal(tg, []string{"/var/lib/data"}) {
		t.Errorf("image volumes: %v", tg)
	}

	// explicit mount on the same target wins: no duplicate mount point
	got = rewritten(t, `{"Image":"withvol","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/var/lib/data"}]}}`)
	if tg := anonTargets(t, got); len(tg) != 0 {
		t.Errorf("duplicate target: %v", tg)
	}

	got = rewritten(t, `{"Image":"withvol","HostConfig":{"Binds":["myvol:/var/lib/data"]}}`)
	if tg := anonTargets(t, got); len(tg) != 0 {
		t.Errorf("duplicate target (bind): %v", tg)
	}

	// VolumesFrom: inherited targets unknown, leave alone
	got = rewritten(t, `{"Image":"withvol","HostConfig":{"VolumesFrom":["mine"]}}`)
	if tg := anonTargets(t, got); len(tg) != 0 {
		t.Errorf("volumes-from: %v", tg)
	}

	// nothing anonymous: body untouched
	r := newReq("POST", "/containers/create", `{"Image":"alpine:3.19"}`)
	if err := checkWith(t, newWorld(), ModeFull, r); err != nil {
		t.Fatal(err)
	}

	b, _ := io.ReadAll(r.Body)
	if string(b) != `{"Image":"alpine:3.19"}` {
		t.Errorf("body modified: %s", b)
	}
}

func listResponse(t *testing.T, mode Mode, path, body string) string {
	t.Helper()

	iso, _ := New(testName, mode)
	req := newReq("GET", path, "")
	resp := &http.Response{
		StatusCode: 200, Request: req, Header: http.Header{},
		Body: io.NopCloser(strings.NewReader(body)),
	}

	if err := iso.FilterResponse(resp); err != nil {
		t.Fatal(err)
	}

	b, _ := io.ReadAll(resp.Body)
	if resp.ContentLength != -1 && resp.ContentLength != int64(len(b)) && resp.ContentLength != 0 {
		t.Errorf("ContentLength %d != %d", resp.ContentLength, len(b))
	}

	return string(b)
}

func TestFilterImageList(t *testing.T) {
	body := `[{"Id":"a","Labels":{"` + LabelKey + `":"dev"}},{"Id":"b","Labels":{"` + LabelKey + `":"x"}},{"Id":"c","Labels":null},{"Id":"d"}]`

	got := listResponse(t, ModeFull, "/v1.44/images/json", body)
	if strings.Contains(got, `"b"`) || !strings.Contains(got, `"a"`) || !strings.Contains(got, `"c"`) || !strings.Contains(got, `"d"`) {
		t.Errorf("full: %s", got)
	}

	if got := listResponse(t, ModeWrites, "/images/json", body); got != body {
		t.Errorf("writes mode must not filter: %s", got)
	}

	if got := listResponse(t, ModeFull, "/containers/json", `[{"Id":"zz"}]`); got != `[{"Id":"zz"}]` {
		t.Errorf("other endpoints must pass through: %s", got)
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

// maskWorld adds shared images with tags, as the daemon reports them.
func maskWorld() *fake {
	f := newWorld()
	f.docs["/images/sha256:aaa/json"] = map[string]any{"RepoTags": []any{"alpine:3.19"}, "Config": map[string]any{"Labels": nil}}
	f.docs["/images/sha256:bbb/json"] = map[string]any{"RepoTags": []any{"evil/img:1"}, "RepoDigests": []any{"evil/img@sha256:bbb"}, "Config": map[string]any{}}
	f.docs["/images/sha256:ccc/json"] = map[string]any{"Config": map[string]any{}} // untagged
	f.docs["/images/evil/img:1/json"] = f.docs["/images/sha256:bbb/json"]
	f.docs["/images/alpine:3.19/json"] = f.docs["/images/sha256:aaa/json"]

	return f
}

// allowOnly permits shared images having a reference with one of the prefixes.
func allowOnly(prefixes ...string) func([]string) bool {
	return func(refs []string) bool {
		for _, r := range refs {
			for _, p := range prefixes {
				if strings.HasPrefix(r, p) {
					return true
				}
			}
		}

		return false
	}
}

func checkMasked(t *testing.T, mode Mode, r *http.Request) error {
	t.Helper()

	iso, _ := New(testName, mode)
	iso.ImageVisible = allowOnly("alpine")

	return iso.CheckAccess(context.Background(), maskWorld().client(t), r)
}

func TestAllowedImagesMaskSharedImages(t *testing.T) {
	tests := []struct {
		method, path, body string
		wantErr            bool
	}{
		// inspect: by name, and by ID (resolved through its tags)
		{"GET", "/images/alpine:3.19/json", "", false},
		{"GET", "/images/sha256:aaa/json", "", false},
		{"GET", "/images/evil/img:1/json", "", true},
		{"GET", "/images/sha256:bbb/json", "", true},
		{"GET", "/images/sha256:ccc/json", "", true}, // untagged: nothing matches
		{"GET", "/images/evil/img:1/history", "", true},
		// own images are always visible, even though no pattern matches
		{"GET", "/images/myimg/json", "", false},
		{"DELETE", "/images/myimg", "", false},
		// create
		{"POST", "/containers/create", `{"Image":"alpine:3.19"}`, false},
		{"POST", "/containers/create", `{"Image":"sha256:aaa"}`, false},
		{"POST", "/containers/create", `{"Image":"myimg"}`, false},
		{"POST", "/containers/create", `{"Image":"evil/img:1"}`, true},
		{"POST", "/containers/create", `{"Image":"sha256:bbb"}`, true},
		{"POST", "/containers/create", `{"Image":"otherimg"}`, true},
		{"POST", "/containers/create", `{"Image":"notpulledyet"}`, false}, // daemon 404s, client pulls (checked by policy)
		// export
		{"GET", "/images/get?names=alpine:3.19", "", false},
		{"GET", "/images/get?names=evil/img:1", "", true},
	}

	for _, mode := range []Mode{ModeFull, ModeWrites} {
		for _, tc := range tests {
			// in writes mode reads are not isolated by definition
			if mode == ModeWrites && tc.method == "GET" {
				continue
			}

			err := checkMasked(t, mode, newReq(tc.method, tc.path, tc.body))
			if (err != nil) != tc.wantErr {
				t.Errorf("%s %s %s %s: err=%v wantErr=%v", mode, tc.method, tc.path, tc.body, err, tc.wantErr)
			}
		}
	}
}

func TestAllowedImagesMaskImageList(t *testing.T) {
	iso, _ := New(testName, ModeFull)
	iso.ImageVisible = allowOnly("alpine")

	body := `[` +
		`{"Id":"own","Labels":{"` + LabelKey + `":"dev"}},` +
		`{"Id":"foreign","Labels":{"` + LabelKey + `":"x"}},` +
		`{"Id":"alp","RepoTags":["alpine:3.19"]},` +
		`{"Id":"alpdig","RepoTags":null,"RepoDigests":["alpine@sha256:ff"]},` +
		`{"Id":"evil","RepoTags":["evil/img:1"]},` +
		`{"Id":"untagged","RepoTags":null}]`

	resp := &http.Response{StatusCode: 200, Request: newReq("GET", "/images/json", ""), Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	if err := iso.FilterResponse(resp); err != nil {
		t.Fatal(err)
	}

	b, _ := io.ReadAll(resp.Body)

	var got []map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	var ids []string
	for _, img := range got {
		ids = append(ids, img["Id"].(string))
	}

	if want := []string{"own", "alp", "alpdig"}; !slices.Equal(ids, want) {
		t.Errorf("visible = %v, want %v", ids, want)
	}
}
