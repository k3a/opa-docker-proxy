// Package isolation implements an optional isolation feature.
//
// When enabled, every resource created through the proxy (containers, volumes,
// networks, images built) gets a unique label injected.  Operations on
// individual resources are checked for the label before being forwarded to
// the Docker daemon, and create requests may not reference (mount, join,
// attach to) resources that lack it.
//
// Two modes control what is isolated:
//
//   - ModeFull (default): the client sees a private daemon. List operations
//     and events are filtered by label and every per-resource request,
//     reads included, is checked.
//   - ModeWrites: reads are untouched; only requests that change something
//     are checked (and prune is scoped by label).
//
// Images need special treatment because a pull can not be labelled. They have
// three states: "ours" (built or committed through this proxy, labelled),
// "foreign" (labelled for another isolation name: unusable) and "shared"
// (unlabelled: pulled or public; usable but read-only, i.e. can not be
// deleted, pushed or tagged through the proxy).
//
// The entire package is self-contained and can be removed by deleting the
// isolation/ directory, removing the flag handling in main.go, and removing
// the ~15 lines in proxy.go that call into Isolation.
package isolation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/k3a/opa-docker-proxy/utils"
)

// LabelKey is the Docker label key injected on every isolated resource.
const LabelKey = "io.opa-docker-proxy.isolation"

// ResourceType identifies the kind of Docker resource.
type ResourceType int

// Resource type identifiers for Docker API resources.
const (
	ResourceContainer ResourceType = iota
	ResourceImage
	ResourceVolume
	ResourceNetwork
	ResourceExec
)

func (rt ResourceType) String() string {
	switch rt {
	case ResourceContainer:
		return "container"
	case ResourceImage:
		return "image"
	case ResourceVolume:
		return "volume"
	case ResourceNetwork:
		return "network"
	case ResourceExec:
		return "exec"
	default:
		return fmt.Sprintf("ResourceType(%d)", int(rt))
	}
}

// Isolation carries the isolation name and provides methods for transforming
// Docker API requests so that the Docker daemon only sees/affects resources
// belonging to this isolation context.
type Isolation struct {
	Name string
	Mode Mode

	// ImageVisible, when set, decides whether a shared (unlabelled) image may
	// be seen and used, given its references: the name the client used plus
	// its repo tags and digests. It is how policy.allowed_images masks pulled
	// images. Nil means every shared image is visible.
	ImageVisible func(refs []string) bool
}

// Mode selects how much of the Docker API is isolated.
type Mode string

// Isolation modes.
const (
	// ModeFull isolates reads and writes: the client sees a private daemon.
	ModeFull Mode = "full"
	// ModeWrites checks only requests that change something.
	ModeWrites Mode = "writes"
)

// New creates a new Isolation.
// If name is empty the name is derived from a SHA-256 hash of the current
// working directory (first 16 hex characters). An empty mode means ModeFull.
func New(name string, mode Mode) (*Isolation, error) {
	switch mode {
	case "":
		mode = ModeFull
	case ModeFull, ModeWrites:
	default:
		return nil, fmt.Errorf("unknown isolation mode %q (valid: full, writes)", mode)
	}

	if name == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("get working directory: %w", err)
		}

		h := sha256.Sum256([]byte(cwd))
		name = fmt.Sprintf("%x", h[:8])
	}

	return &Isolation{Name: name, Mode: mode}, nil
}

// labelFilterValue returns the value that should appear inside a Docker
// label filter for this isolation context.
func (i *Isolation) labelFilterEntry() map[string]any {
	return map[string]any{LabelKey + "=" + i.Name: true}
}

// pathHasID reports whether the path refers to a specific resource instance
// (e.g. /containers/{id}/stop) as opposed to a collection
// (e.g. /containers/json).
func pathHasID(cleaned string) bool {
	// After the resource prefix there must be at least one path segment that
	// is not a well-known collection action.
	knownActions := map[string]bool{
		"json": true, "create": true, "prune": true, "search": true,
	}

	parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	if len(parts) < 2 {
		return false
	}

	candidate := parts[1]

	return !knownActions[candidate] && candidate != ""
}

// resourceTypeAndID extracts the resource type and ID from a Docker API path.
// Returns (type, id, true) on success, or (_, _, false) for list/create paths.
func resourceTypeAndID(path string) (ResourceType, string, bool) {
	cleaned := utils.StripVersionPrefix(path)
	if cleaned == "" || cleaned == "/" {
		return 0, "", false
	}

	// Match resource prefix.
	type entry struct {
		prefix string
		typ    ResourceType
	}

	patterns := []entry{
		{"/containers/", ResourceContainer},
		{"/volumes/", ResourceVolume},
		{"/networks/", ResourceNetwork},
		{"/exec/", ResourceExec},
	}

	for _, p := range patterns {
		if !strings.HasPrefix(cleaned, p.prefix) {
			continue
		}

		if !pathHasID(cleaned) {
			return 0, "", false
		}

		rest := strings.TrimPrefix(cleaned, p.prefix)

		id, _, _ := strings.Cut(rest, "/")
		if id == "" {
			return 0, "", false
		}

		return p.typ, id, true
	}

	return 0, "", false
}

// ---------------------------------------------------------------------------
// Request transformations
// ---------------------------------------------------------------------------

// isCollectionListPath returns true when the path is a collection-list
// endpoint that supports the "filters" query parameter.
func isCollectionListPath(path string) bool {
	cleaned := utils.StripVersionPrefix(path)
	// Exact match for list endpoints
	listEndpoints := map[string]bool{
		"/containers/json": true,
		"/volumes":         true,
		"/networks":        true,
		"/events":          true,
	}
	if listEndpoints[cleaned] {
		return true
	}
	// Also handle query-string variants like /containers/json?all=1
	for ep := range listEndpoints {
		if strings.HasPrefix(cleaned, ep+"?") || strings.HasPrefix(cleaned, ep+"&") {
			return true
		}
	}

	return false
}

// isCreatePath returns true when the path is a resource-creation endpoint.
func isCreatePath(path string) bool {
	cleaned := utils.StripVersionPrefix(path)
	createEndpoints := map[string]bool{
		"/containers/create": true,
		"/volumes/create":    true,
		"/networks/create":   true,
	}

	return createEndpoints[cleaned]
}

// isCommitPath returns true for the endpoint that turns a container into an
// image.
func isCommitPath(path string) bool {
	return utils.StripVersionPrefix(path) == "/commit"
}

// setBody replaces the request body and fixes the length headers so the
// reverse proxy doesn't forward a stale Content-Length to Docker.
func setBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
}

// isBuildPath returns true when the path is the Docker build endpoint.
func isBuildPath(path string) bool {
	cleaned := utils.StripVersionPrefix(path)

	return cleaned == "/build"
}

// isPrunePath returns true when the path is a prune endpoint.
func isPrunePath(path string) bool {
	cleaned := utils.StripVersionPrefix(path)
	pruneEndpoints := map[string]bool{
		"/containers/prune": true,
		"/images/prune":     true,
		"/volumes/prune":    true,
		"/networks/prune":   true,
		"/build/prune":      true,
	}

	return pruneEndpoints[cleaned]
}

// ---------------------------------------------------------------------------
// Public API methods
// ---------------------------------------------------------------------------

var attachWSPath = regexp.MustCompile(`^/containers/[^/]+/attach/ws$`)

// isWriteRequest reports whether a request can change state. Websocket attach
// is a GET but can send input to the container, so it counts as a write.
func isWriteRequest(method, path string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return true
	}

	return attachWSPath.MatchString(utils.StripVersionPrefix(path))
}

// skip reports whether the request is outside this mode's scope.
func (i *Isolation) skip(r *http.Request) bool {
	return i.Mode == ModeWrites && !isWriteRequest(r.Method, r.URL.Path)
}

// TransformRequest mutates the HTTP request to enforce isolation.
// It should be called after the OPA policy has allowed the request, just
// before forwarding to the Docker daemon.
//
//   - For creation endpoints (POST /containers/create, etc.):
//     injects the isolation label into the JSON body.
//   - For list endpoints (GET /containers/json, etc.):
//     injects a label filter into the "filters" query parameter.
//   - For the build endpoint: injects the label into the "labels" query param.
//   - For prune endpoints: injects a label filter to avoid deleting resources
//     from other isolation contexts.
func (i *Isolation) TransformRequest(r *http.Request) {
	if r == nil || i.skip(r) {
		return
	}

	path := r.URL.Path

	switch {
	case isCreatePath(path) || isCommitPath(path):
		// Inject labels into JSON body
		body, err := io.ReadAll(r.Body)
		if errc := r.Body.Close(); errc != nil {
			slog.Warn("failed to close request body", "error", errc)
		}

		if err != nil {
			return
		}

		// commit takes an optional body; make sure there is one to label.
		if isCommitPath(path) && len(bytes.TrimSpace(body)) == 0 {
			body = []byte("{}")

			r.Header.Set("Content-Type", "application/json")
		}

		setBody(r, i.injectBodyLabels(body))

	case isBuildPath(path):
		i.injectBuildLabels(r.URL)

	case isCollectionListPath(path) || isPrunePath(path):
		i.injectFilters(r.URL)
	}
}

// CheckAccess verifies that the resources a request touches belong to this
// isolation context.  It makes additional API calls to the Docker daemon to
// inspect them.
//
//   - The resource addressed by the path (exec instances resolve to their
//     parent container).
//   - For network connect/disconnect: the container named in the body.
//   - For container creation: every container, network and volume the body
//     references (VolumesFrom, "container:" modes, Links, networks, named
//     volumes). Names that do not exist yet are left to the daemon.
//
// Returns nil when access is granted, or an error describing why it was denied.
func (i *Isolation) CheckAccess(ctx context.Context, dockerClient *http.Client, r *http.Request) error {
	if i.skip(r) {
		return nil
	}

	if err := i.checkTarget(ctx, dockerClient, r.Method, r.URL.Path); err != nil {
		return err
	}

	return i.checkReferences(ctx, dockerClient, r)
}

// checkTarget checks the resource addressed by the request path.
func (i *Isolation) checkTarget(ctx context.Context, dockerClient *http.Client, method, path string) error {
	if name, write, ok := imageTarget(utils.StripVersionPrefix(path), method); ok {
		return i.checkImage(ctx, dockerClient, name, write)
	}

	rt, id, ok := resourceTypeAndID(path)
	if !ok {
		return nil // not a resource-specific endpoint
	}

	if rt == ResourceExec {
		return i.checkExecContainer(ctx, dockerClient, id)
	}

	ok, reason, err := i.checkResource(ctx, dockerClient, rt, id)
	if err != nil {
		return fmt.Errorf("isolation check for %v %s: %w", rt, id, err)
	}

	if !ok {
		return fmt.Errorf("access denied: %s", reason)
	}

	return nil
}

var networkMembershipPath = regexp.MustCompile(`^/networks/[^/]+/(connect|disconnect)$`)

// readJSONBody reads the request body as a JSON object and restores it.
// ok is false when the body is not a JSON object.
func readJSONBody(r *http.Request) (data map[string]any, ok bool, err error) {
	body, err := io.ReadAll(r.Body)
	if errc := r.Body.Close(); errc != nil {
		slog.Warn("failed to close request body", "error", errc)
	}

	if err != nil {
		return nil, false, fmt.Errorf("read request body: %w", err)
	}

	r.Body = io.NopCloser(bytes.NewReader(body))

	if len(bytes.TrimSpace(body)) == 0 {
		return nil, false, nil // no body: the daemon rejects it itself
	}

	// The daemon may decode a body the proxy could not (e.g. trailing data),
	// so an unparseable body must not skip the ownership checks.
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, false, fmt.Errorf("request body is not a valid JSON object: %w", err)
	}

	return data, true, nil
}

// checkReferences checks resources named in query or body of a request.
func (i *Isolation) checkReferences(ctx context.Context, client *http.Client, r *http.Request) error {
	cleaned := utils.StripVersionPrefix(r.URL.Path)

	var refs []reference

	switch {
	case r.Method == http.MethodPost && cleaned == "/containers/create":
		return i.checkCreate(ctx, client, r)

	case r.Method == http.MethodPost && networkMembershipPath.MatchString(cleaned):
		data, ok, err := readJSONBody(r)
		if err != nil || !ok {
			return err
		}

		refs = membershipReferences(data)

	case r.Method == http.MethodPost && cleaned == "/commit":
		for _, c := range r.URL.Query()["container"] {
			refs = append(refs, reference{typ: ResourceContainer, id: c})
		}

	case r.Method == http.MethodGet && cleaned == "/images/get":
		for _, n := range r.URL.Query()["names"] {
			refs = append(refs, reference{typ: ResourceImage, id: n})
		}

	default:
		return nil
	}

	_, err := i.checkRefs(ctx, client, refs)

	return err
}

// checkRefs denies references to foreign resources. It returns the
// references that do not exist (yet).
func (i *Isolation) checkRefs(ctx context.Context, client *http.Client, refs []reference) ([]reference, error) {
	var missing []reference

	for _, ref := range refs {
		st, err := i.ownership(ctx, client, ref.typ, ref.id)
		if err != nil {
			return nil, fmt.Errorf("isolation check for %v %s: %w", ref.typ, ref.id, err)
		}

		switch st {
		case foreign:
			return nil, fmt.Errorf("access denied: referenced %v %q is not part of this isolation context", ref.typ, ref.id)
		case hidden:
			return nil, fmt.Errorf("access denied: image %q is not permitted (policy.allowed_images)", ref.id)
		case notFound:
			missing = append(missing, ref)
		case owned, shared:
		}
	}

	return missing, nil
}

type ownershipState int

const (
	owned ownershipState = iota
	foreign
	notFound
	// shared is an unlabelled image: usable by everyone, owned by no one.
	shared
	// hidden is a shared image that policy.allowed_images does not permit.
	hidden
)

// checkResource inspects a Docker resource and verifies it carries the
// isolation label. A missing resource is reported as not accessible.
func (i *Isolation) checkResource(ctx context.Context, client *http.Client, rt ResourceType, id string) (bool, string, error) {
	st, err := i.ownership(ctx, client, rt, id)
	if err != nil {
		return false, "", err
	}

	switch st {
	case owned:
		return true, "", nil
	case notFound:
		return false, "resource not found", nil
	default:
		return false, fmt.Sprintf("resource lacks isolation label %s=%s", LabelKey, i.Name), nil
	}
}

// inspectJSON GETs an inspect path from the daemon. found is false on 404.
func inspectJSON(ctx context.Context, client *http.Client, inspectPath string) (data map[string]any, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+inspectPath, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("inspect %s: %w", inspectPath, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close inspect body", "error", err, "path", inspectPath)
		}
	}()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, false, nil
	case http.StatusOK:
		// proceed
	default:
		return nil, false, fmt.Errorf("inspect %s returned HTTP %d", inspectPath, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read inspect body: %w", err)
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, false, fmt.Errorf("parse inspect response: %w", err)
	}

	return data, true, nil
}

// ownership inspects a resource and classifies it.
func (i *Isolation) ownership(ctx context.Context, client *http.Client, rt ResourceType, id string) (ownershipState, error) {
	// id may come from a request body: escape it so it can not alter the
	// inspected path.
	var inspectPath string

	switch rt {
	case ResourceContainer:
		inspectPath = "/containers/" + url.PathEscape(id) + "/json"
	case ResourceImage:
		inspectPath = "/images/" + escapeRef(id) + "/json"
	case ResourceVolume:
		inspectPath = "/volumes/" + url.PathEscape(id)
	case ResourceNetwork:
		inspectPath = "/networks/" + url.PathEscape(id)
	default:
		return foreign, fmt.Errorf("unsupported resource type %v", rt)
	}

	data, found, err := inspectJSON(ctx, client, inspectPath)
	if err != nil {
		return foreign, err
	}

	if !found {
		return notFound, nil
	}

	// Docker resources store labels in different places:
	//   - Containers: .Config.Labels
	//   - Volumes:    top-level .Labels
	//   - Networks:   top-level .Labels
	//   - Images:     .Config.Labels (set at build/commit time only)
	var labels map[string]any
	if cfg, ok := data["Config"].(map[string]any); ok {
		labels, _ = cfg["Labels"].(map[string]any)
	} else if l, ok := data["Labels"].(map[string]any); ok {
		labels = l
	}

	val, labelled := labels[LabelKey]

	switch {
	case labelled && fmt.Sprint(val) == i.Name:
		return owned, nil
	case !labelled && rt == ResourceImage:
		if i.ImageVisible != nil && !i.ImageVisible(imageRefs(id, data)) {
			return hidden, nil
		}

		return shared, nil
	default:
		return foreign, nil
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// injectBodyLabels adds the isolation label to a JSON request body.
// Docker matches JSON keys case-insensitively, so differently-cased variants
// of "Labels" are merged first; otherwise one could override the injected
// label. Volumes implicitly created through HostConfig.Mounts are labelled
// too.
func (i *Isolation) injectBodyLabels(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return body
	}

	var data map[string]any
	if err := json.Unmarshal(trimmed, &data); err != nil {
		return body // not JSON – leave unchanged
	}

	i.setLabel(data, "Labels")

	for _, hc := range objects(lookup(data, "HostConfig")) {
		for _, mount := range objects(lookup(hc, "Mounts")) {
			if strings.EqualFold(fmt.Sprint(first(lookup(mount, "Type"))), "volume") {
				vo := mergeObjects(mount, "VolumeOptions")
				i.setLabel(vo, "Labels")
			}
		}
	}

	modified, err := json.Marshal(data)
	if err != nil {
		return body
	}

	return modified
}

func first(vs []any) any {
	if len(vs) == 0 {
		return nil
	}

	return vs[0]
}

// mergeObjects collapses all case variants of key in m into one object stored
// under key, creating it when absent, and returns it.
func mergeObjects(m map[string]any, key string) map[string]any {
	merged := make(map[string]any)

	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}

		if obj, ok := v.(map[string]any); ok {
			maps.Copy(merged, obj)
		}

		delete(m, k)
	}

	m[key] = merged

	return merged
}

// setLabel sets the isolation label in the Labels-like object under key.
func (i *Isolation) setLabel(m map[string]any, key string) {
	mergeObjects(m, key)[LabelKey] = i.Name
}

// injectFilters adds a label filter to the "filters" query parameter.
func (i *Isolation) injectFilters(u *url.URL) {
	q := u.Query()
	filtersStr := q.Get("filters")

	var filters map[string]any
	if filtersStr != "" {
		if err := json.Unmarshal([]byte(filtersStr), &filters); err != nil {
			slog.Warn("failed to parse existing filters", "error", err)
		}
	}

	if filters == nil {
		filters = make(map[string]any)
	}

	labelFilters, _ := filters["label"].(map[string]any)
	if labelFilters == nil {
		labelFilters = make(map[string]any)
		filters["label"] = labelFilters
	}

	maps.Copy(labelFilters, i.labelFilterEntry())

	encoded, _ := json.Marshal(filters)
	q.Set("filters", string(encoded))
	u.RawQuery = q.Encode()
}

// injectBuildLabels adds the isolation label to the "labels" query parameter
// used by the Docker build API.
func (i *Isolation) injectBuildLabels(u *url.URL) {
	q := u.Query()
	labelsStr := q.Get("labels")

	var labels map[string]any
	if labelsStr != "" {
		if err := json.Unmarshal([]byte(labelsStr), &labels); err != nil {
			slog.Warn("failed to parse existing labels", "error", err)
		}
	}

	if labels == nil {
		labels = make(map[string]any)
	}

	labels[LabelKey] = i.Name
	encoded, _ := json.Marshal(labels)
	q.Set("labels", string(encoded))
	u.RawQuery = q.Encode()
}

// checkExecContainer inspects an exec instance to find its parent container,
// then checks that container for the isolation label.
func (i *Isolation) checkExecContainer(ctx context.Context, client *http.Client, execID string) error {
	data, found, err := inspectJSON(ctx, client, "/exec/"+url.PathEscape(execID)+"/json")
	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("exec instance %s not found", execID)
	}

	containerID, ok := data["ContainerID"].(string)
	if !ok || containerID == "" {
		return fmt.Errorf("exec instance %s has no associated container", execID)
	}

	ok, reason, err := i.checkResource(ctx, client, ResourceContainer, containerID)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("access denied: %s", reason)
	}

	return nil
}

// String returns a human-readable description of the isolation context.
func (i *Isolation) String() string {
	return fmt.Sprintf("isolation=%s mode=%s", i.Name, i.Mode)
}
