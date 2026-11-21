package utils

import "testing"

func TestSplitVersionPath(t *testing.T) {
	tests := []struct{ in, ver, path string }{
		{"/v1.44/containers/json", "v1.44", "/containers/json"},
		{"/v1.44/volumes/create", "v1.44", "/volumes/create"},
		{"/v2/containers/json", "v2", "/containers/json"},
		// Lenient forms accepted by the daemon router (v[0-9.]+).
		{"/v1.45./secrets", "v1.45.", "/secrets"},
		{"/v1..45/configs", "v1..45", "/configs"},
		{"/v./swarm/unlockkey", "v.", "/swarm/unlockkey"},
		{"/v1.45x/secrets", "", "/v1.45x/secrets"},
		{"/containers/json", "", "/containers/json"},
		{"/volumes/create", "", "/volumes/create"}, // not a version
		{"/volumes/myvol", "", "/volumes/myvol"},
		{"/version", "", "/version"},
		{"/v1.44", "", "/v1.44"},
		{"/_ping", "", "/_ping"},
	}
	for _, tc := range tests {
		v, p := SplitVersionPath(tc.in)
		if v != tc.ver || p != tc.path {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", tc.in, v, p, tc.ver, tc.path)
		}
	}
}
