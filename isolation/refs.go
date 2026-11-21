package isolation

import (
	"regexp"
	"strings"
)

// reference is a resource named inside a request body.
type reference struct {
	typ ResourceType
	id  string
}

// builtinNetworks exist on every daemon and carry no label.
var builtinNetworks = map[string]bool{"": true, "default": true, "bridge": true, "none": true, "host": true}

var volumeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

// lookup returns the values of every key equal to name, ignoring case:
// Docker decodes JSON keys case-insensitively, so all variants count.
func lookup(m map[string]any, name string) []any {
	var out []any

	for k, v := range m {
		if strings.EqualFold(k, name) {
			out = append(out, v)
		}
	}

	return out
}

// objects returns the map values among vs, flattening arrays.
func objects(vs []any) []map[string]any {
	var out []map[string]any

	for _, v := range vs {
		switch t := v.(type) {
		case map[string]any:
			out = append(out, t)
		case []any:
			out = append(out, objects(t)...)
		}
	}

	return out
}

// strs returns the string values among vs, flattening arrays.
func strs(vs []any) []string {
	var out []string

	for _, v := range vs {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			out = append(out, strs(t)...)
		}
	}

	return out
}

// containerMode returns the container referenced by a "container:<id>" mode.
func containerMode(mode string) (string, bool) {
	id, ok := strings.CutPrefix(mode, "container:")

	return id, ok && id != ""
}

// createReferences lists the resources a /containers/create body refers to.
func createReferences(body map[string]any) []reference {
	var refs []reference

	container := func(id string) { refs = append(refs, reference{ResourceContainer, id}) }
	network := func(name string) {
		if !builtinNetworks[name] {
			refs = append(refs, reference{ResourceNetwork, name})
		}
	}

	for _, hc := range objects(lookup(body, "HostConfig")) {
		for _, v := range strs(lookup(hc, "VolumesFrom")) {
			id, _, _ := strings.Cut(v, ":")
			container(id)
		}

		for _, v := range strs(lookup(hc, "Links")) {
			id, _, _ := strings.Cut(v, ":")
			container(id)
		}

		for _, key := range []string{"PidMode", "IpcMode", "UTSMode", "CgroupnsMode"} {
			for _, v := range strs(lookup(hc, key)) {
				if id, ok := containerMode(v); ok {
					container(id)
				}
			}
		}

		for _, v := range strs(lookup(hc, "NetworkMode")) {
			if id, ok := containerMode(v); ok {
				container(id)
			} else {
				network(v)
			}
		}

		for _, entry := range strs(lookup(hc, "Binds")) {
			parts := strings.Split(entry, ":")
			if len(parts) >= 2 && volumeName.MatchString(parts[0]) {
				refs = append(refs, reference{ResourceVolume, parts[0]})
			}
		}

		for _, mount := range objects(lookup(hc, "Mounts")) {
			for _, t := range strs(lookup(mount, "Type")) {
				if t != "volume" {
					continue
				}

				for _, src := range strs(lookup(mount, "Source")) {
					if src != "" {
						refs = append(refs, reference{ResourceVolume, src})
					}
				}
			}
		}
	}

	for _, nc := range objects(lookup(body, "NetworkingConfig")) {
		for _, endpoints := range objects(lookup(nc, "EndpointsConfig")) {
			for name := range endpoints {
				network(name)
			}
		}
	}

	return refs
}

// membershipReferences lists the container named in a network
// connect/disconnect body.
func membershipReferences(body map[string]any) []reference {
	var refs []reference

	for _, id := range strs(lookup(body, "Container")) {
		refs = append(refs, reference{ResourceContainer, id})
	}

	return refs
}
