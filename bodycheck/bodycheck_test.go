package bodycheck

import (
	"strings"
	"testing"
)

const jsonCT = "application/json"

func TestParse(t *testing.T) {
	tests := []struct {
		name, method, path, ct, body string
		wantErr                      string // substring; "" = ok
	}{
		{"plain create", "POST", "/containers/create", jsonCT, `{"Image":"alpine","HostConfig":{"Privileged":false}}`, ""},
		{"charset and case in content type", "POST", "/containers/create", "Application/JSON; charset=utf-8", `{"Image":"a"}`, ""},

		// case-insensitive keys
		{"lowercase hostconfig", "POST", "/containers/create", jsonCT, `{"hostconfig":{"privileged":true}}`, "non-canonical"},
		{"upper hostconfig", "POST", "/containers/create", jsonCT, `{"HOSTCONFIG":{}}`, "non-canonical"},
		{"nested lowercase", "POST", "/containers/create", jsonCT, `{"HostConfig":{"privileged":true}}`, "HostConfig.privileged"},
		{"long s folds to s", "POST", "/containers/create", jsonCT, "{\"HoſtConfig\":{}}", "non-canonical"},
		{"kelvin sign folds to k", "POST", "/containers/create", jsonCT, "{\"HostConfig\":{\"NetworKMode\":\"host\"}}", "non-canonical"},
		{"mount type lowercase", "POST", "/containers/create", jsonCT, `{"HostConfig":{"Mounts":[{"Type":"volume"},{"type":"bind","source":"/"}]}}`, "Mounts.type"},
		{"deep driver options", "POST", "/containers/create", jsonCT, `{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"driverconfig":{}}}]}}`, "DriverConfig"},
		{"image lowercase", "POST", "/containers/create", jsonCT, `{"image":"x"}`, "non-canonical"},
		{"networking config", "POST", "/containers/create", jsonCT, `{"networkingconfig":{}}`, "non-canonical"},
		{"connect container", "POST", "/networks/n1/connect", jsonCT, `{"container":"x"}`, "non-canonical"},
		{"connect ok", "POST", "/networks/n1/connect", jsonCT, `{"Container":"x"}`, ""},

		// data keys and unknown fields are not touched
		{"labels are data", "POST", "/containers/create", jsonCT, `{"Labels":{"image":"x","IMAGE":"y","hostconfig":"z"}}`, ""},
		{"endpoint names are data", "POST", "/containers/create", jsonCT, `{"NetworkingConfig":{"EndpointsConfig":{"Type":{},"type":{}}}}`, ""},
		{"tmpfs paths are data", "POST", "/containers/create", jsonCT, `{"HostConfig":{"Tmpfs":{"/Source":"","/source":""}}}`, ""},
		{"unknown fields", "POST", "/containers/create", jsonCT, `{"healthcheck":{"test":["CMD","x"]},"HostConfig":{"memory":1}}`, ""},
		{"other endpoints unchecked", "POST", "/volumes/create", jsonCT, `{"name":"v","hostconfig":1}`, ""},
		{"non-create path", "POST", "/containers/abc/exec", jsonCT, `{"hostconfig":1}`, ""},

		// duplicate keys
		{"dup hostconfig", "POST", "/containers/create", jsonCT, `{"HostConfig":{"Privileged":true},"HostConfig":{"Binds":[]}}`, "duplicate"},
		{"dup nested", "POST", "/containers/create", jsonCT, `{"HostConfig":{"Privileged":true,"Privileged":false}}`, "duplicate"},
		{"dup in array element", "POST", "/containers/create", jsonCT, `{"HostConfig":{"Mounts":[{"Type":"bind","Type":"volume"}]}}`, "duplicate"},
		{"dup via escape", "POST", "/containers/create", jsonCT, `{"HostConfig":{},"HostConfig":{"Privileged":true}}`, "duplicate"},
		{"dup on unchecked endpoint", "POST", "/containers/abc/exec", jsonCT, `{"a":1,"a":2}`, "duplicate"},
		{"dup in labels", "POST", "/containers/create", jsonCT, `{"Labels":{"a":"1","a":"2"}}`, "duplicate"},
		{"distinct keys fine", "POST", "/containers/create", jsonCT, `{"Labels":{"a":"1","b":"2"},"Cmd":["x"],"n":1.5,"z":null}`, ""},

		// content type / syntax
		{"non-json create", "POST", "/containers/create", "text/plain", `{"HostConfig":{"Privileged":true}}`, "Content-Type"},
		{"no content type create", "POST", "/containers/create", "", `{"HostConfig":{"Privileged":true}}`, "Content-Type"},
		{"non-json commit", "POST", "/commit", "text/plain", `{}`, "Content-Type"},
		{"non-json connect", "POST", "/networks/n/connect", "text/plain", `{"Container":"x"} junk`, "Content-Type"},
		{"empty create body", "POST", "/containers/create", "", ``, ""},
		{"non-json elsewhere is opaque", "POST", "/build", "application/x-tar", "tar bytes", ""},
		{"invalid json", "POST", "/containers/create", jsonCT, `{"a":`, "invalid JSON"},
		{"trailing junk", "POST", "/containers/create", jsonCT, `{"Image":"a"} junk`, "invalid JSON"},
		{"GET with body is not schema-checked", "GET", "/containers/create", jsonCT, `{"hostconfig":1}`, ""},
	}

	for _, tc := range tests {
		_, err := Parse(tc.method, tc.path, tc.ct, []byte(tc.body))

		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s: expected error containing %q", tc.name, tc.wantErr)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s: error %q does not contain %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestParseReturnsValue(t *testing.T) {
	v, err := Parse("POST", "/containers/create", jsonCT, []byte(`{"Image":"a","HostConfig":{"Privileged":true}}`))
	if err != nil {
		t.Fatal(err)
	}

	m, _ := v.(map[string]any)
	if m["Image"] != "a" || m["HostConfig"].(map[string]any)["Privileged"] != true {
		t.Errorf("parsed = %v", v)
	}

	if v, err := Parse("GET", "/x", "", nil); v != nil || err != nil {
		t.Errorf("no body: %v %v", v, err)
	}

	if v, err := Parse("POST", "/build", "application/x-tar", []byte("x")); v != nil || err != nil {
		t.Errorf("non-json: %v %v", v, err)
	}
}

func TestParseRejectsFormBody(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH"} {
		if _, err := Parse(m, "/images/create", "application/x-www-form-urlencoded; charset=utf-8", []byte("fromImage=evil")); err == nil {
			t.Errorf("%s: expected error for form body", m)
		}
	}

	if _, err := Parse("POST", "/images/create", "application/x-www-form-urlencoded", nil); err != nil {
		t.Errorf("empty form body should pass: %v", err)
	}
}
