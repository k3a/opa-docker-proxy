// Package bodycheck makes sure the request body the policies (and the
// isolation code) inspect is the same one the Docker daemon will act on.
//
// Docker decodes request bodies with encoding/json into structs, which
//
//   - matches object keys case-insensitively: {"hostconfig":{"privileged":true}}
//     sets HostConfig.Privileged, but a rule reading input.body.HostConfig
//     would not see it;
//   - merges duplicate keys: {"HostConfig":{"Privileged":true},"HostConfig":{}}
//     is privileged, while a decode into a map keeps only the last value.
//
// Instead of trying to model Docker's decoder, ambiguous bodies are rejected:
//
//   - an exact duplicate key anywhere in a JSON body is an error;
//   - on the endpoints whose bodies are inspected, the keys the policies read
//     (see the schemas below) must be spelled exactly as in the Docker API;
//     a different case is an error. Every real client (docker CLI, compose,
//     SDKs) uses the canonical spelling.
//   - urlencoded form bodies are rejected on POST/PUT/PATCH: the daemon merges
//     them into the query parameters (body first), which the policies and the
//     isolation code do not see;
//   - those endpoints require Content-Type: application/json, so that the
//     body is always parsed the same way.
//
// Fields not listed in a schema are not checked; map-valued fields (Labels,
// EndpointsConfig, Tmpfs, ...) are opaque on purpose, their keys are data.
// A policy that reads a body field which is not in the schema must add it
// here, otherwise it can be bypassed by spelling the key differently.
package bodycheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"regexp"
	"strings"
)

// schema lists the struct fields of a JSON object that policies read. A nil
// child means "leaf or opaque": no further keys are checked below it.
// Arrays are checked element-wise.
type schema map[string]schema

var containerCreate = schema{
	"Image":   nil,
	"Labels":  nil,
	"Volumes": nil,
	"HostConfig": {
		"Privileged":        nil,
		"NetworkMode":       nil,
		"PidMode":           nil,
		"IpcMode":           nil,
		"UTSMode":           nil,
		"UsernsMode":        nil,
		"CgroupnsMode":      nil,
		"Devices":           nil,
		"DeviceCgroupRules": nil,
		"DeviceRequests":    nil,
		"SecurityOpt":       nil,
		"CapAdd":            nil,
		"Binds":             nil,
		"VolumesFrom":       nil,
		"Links":             nil,
		"VolumeDriver":      nil,
		"Tmpfs":             nil,
		"Mounts": {
			"Type":   nil,
			"Source": nil,
			"Target": nil,
			"VolumeOptions": {
				"Labels":       nil,
				"DriverConfig": {"Name": nil, "Options": nil},
			},
		},
	},
	"NetworkingConfig": {"EndpointsConfig": nil},
}

var execCreate = schema{"Privileged": nil, "User": nil}

var volumeCreate = schema{"Driver": nil, "DriverOpts": nil}

var networkMembership = schema{"Container": nil}

var (
	containerCreatePath   = regexp.MustCompile(`^/containers/create$`)
	execCreatePath        = regexp.MustCompile(`^/containers/[^/]+/exec$`)
	volumeCreatePath      = regexp.MustCompile(`^/volumes/create$`)
	networkMembershipPath = regexp.MustCompile(`^/networks/[^/]+/(connect|disconnect)$`)
	// Other POST endpoints whose JSON body is inspected or rewritten.
	structuredPath = regexp.MustCompile(`^/(containers/create|containers/[^/]+/exec|commit|networks/create|volumes/create|networks/[^/]+/(connect|disconnect))$`)
)

// IsJSON reports whether a Content-Type header denotes JSON, the way the
// Docker daemon decides it.
func IsJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)

	return err == nil && mt == "application/json"
}

// IsForm reports whether a Content-Type header denotes a urlencoded form body,
// which the Docker daemon (Go's ParseForm) merges into the query parameters.
func IsForm(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)

	return err == nil && mt == "application/x-www-form-urlencoded"
}

// Parse validates a request body and, for JSON bodies, returns the parsed
// value. path is the API path without version prefix. For a non-JSON body it
// returns (nil, nil); a non-JSON body on an endpoint whose body is inspected
// is an error.
func Parse(method, path, contentType string, body []byte) (any, error) {
	if len(body) == 0 {
		return nil, nil //nolint:nilnil // no body, nothing to parse
	}

	if IsForm(contentType) && (method == "POST" || method == "PUT" || method == "PATCH") {
		// The daemon calls r.ParseForm(), which merges body values ahead of
		// the query string; the policies and isolation only see the query.
		return nil, errors.New("Content-Type application/x-www-form-urlencoded is not allowed") //nolint:staticcheck // user-facing message
	}

	if !IsJSON(contentType) {
		if method == "POST" && structuredPath.MatchString(path) {
			return nil, errors.New("Content-Type must be application/json for this request") //nolint:staticcheck // user-facing message
		}

		return nil, nil //nolint:nilnil // not JSON: opaque to the policies
	}

	if !json.Valid(body) {
		return nil, errors.New("invalid JSON in request body")
	}

	if err := checkDuplicateKeys(body); err != nil {
		return nil, err
	}

	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("cannot parse request body as JSON: %w", err)
	}

	if method == "POST" {
		var s schema

		switch {
		case containerCreatePath.MatchString(path):
			s = containerCreate
		case execCreatePath.MatchString(path):
			s = execCreate
		case volumeCreatePath.MatchString(path):
			s = volumeCreate
		case networkMembershipPath.MatchString(path):
			s = networkMembership
		}

		if s != nil {
			if err := s.check(parsed, ""); err != nil {
				return nil, err
			}
		}
	}

	return parsed, nil
}

// check verifies that no key of v is a differently-cased spelling of a schema
// field.
func (s schema) check(v any, path string) error {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if err := s.check(e, path); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, child := range t {
			if sub, ok := s[key]; ok {
				if sub != nil {
					if err := sub.check(child, path+key+"."); err != nil {
						return err
					}
				}

				continue
			}

			for canonical := range s {
				if strings.EqualFold(key, canonical) {
					return fmt.Errorf("non-canonical JSON key %q: the Docker API spells it %q", path+key, path+canonical)
				}
			}
		}
	}

	return nil
}

// checkDuplicateKeys rejects any JSON object that has the same key twice.
// The input must be valid JSON.
func checkDuplicateKeys(data []byte) error {
	return walk(json.NewDecoder(bytes.NewReader(data)))
}

func walk(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}

	switch delim {
	case '{':
		seen := map[string]bool{}

		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}

			key, _ := kt.(string)
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}

			seen[key] = true

			if err := walk(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walk(dec); err != nil {
				return err
			}
		}
	}

	_, err = dec.Token() // closing delimiter

	return err
}
