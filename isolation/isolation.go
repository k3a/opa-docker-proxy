// Package isolation implements an optional isolation feature.
//
// When enabled, every resource created through the proxy (containers, volumes,
// networks, images built) gets a unique label injected.  List operations are
// transparently filtered to show only resources bearing that label, and
// operations on individual resources are checked for the label before being
// forwarded to the Docker daemon.
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
	"net/http"
	"net/url"
	"os"
	"strings"
)

// LabelKey is the Docker label key injected on every isolated resource.
const LabelKey = "io.opa-docker-proxy.isolation"

// ResourceType identifies the kind of Docker resource.
type ResourceType int

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
}

// New creates a new Isolation.
// If name is empty the name is derived from a SHA-256 hash of the current
// working directory (first 16 hex characters).
func New(name string) (*Isolation, error) {
	if name == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("get working directory: %w", err)
		}
		h := sha256.Sum256([]byte(cwd))
		name = fmt.Sprintf("%x", h[:8])
	}
	return &Isolation{Name: name}, nil
}

// labelFilterValue returns the value that should appear inside a Docker
// label filter for this isolation context.
func (i *Isolation) labelFilterEntry() map[string]interface{} {
	return map[string]interface{}{LabelKey + "=" + i.Name: true}
}

// ---------------------------------------------------------------------------
// URL path helpers – determine what kind of Docker API endpoint we are
// hitting.
// ---------------------------------------------------------------------------

// stripVersionPrefix strips an optional /v1.xx prefix from a Docker API path.
func stripVersionPrefix(path string) string {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) < 2 {
		return path
	}
	if len(parts[0]) > 0 && parts[0][0] == 'v' {
		return "/" + parts[1]
	}
	return path
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
	cleaned := stripVersionPrefix(path)
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
		{"/images/", ResourceImage},
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
		id := strings.SplitN(rest, "/", 2)[0]
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
	cleaned := stripVersionPrefix(path)
	// Exact match for list endpoints
	listEndpoints := map[string]bool{
		"/containers/json": true,
		"/images/json":     true,
		"/volumes":         true,
		"/networks":        true,
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
	cleaned := stripVersionPrefix(path)
	createEndpoints := map[string]bool{
		"/containers/create": true,
		"/volumes/create":    true,
		"/networks/create":   true,
	}
	return createEndpoints[cleaned]
}

// isBuildPath returns true when the path is the Docker build endpoint.
func isBuildPath(path string) bool {
	cleaned := stripVersionPrefix(path)
	return cleaned == "/build"
}

// isPrunePath returns true when the path is a prune endpoint.
func isPrunePath(path string) bool {
	cleaned := stripVersionPrefix(path)
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
	if r == nil {
		return
	}
	path := r.URL.Path

	switch {
	case isCreatePath(path):
		// Inject labels into JSON body
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return
		}
		modified := i.injectBodyLabels(body)
		r.Body = io.NopCloser(bytes.NewReader(modified))
		// Update Content-Length to match the new body size so the
		// reverse proxy doesn't forward a stale length to Docker.
		r.ContentLength = int64(len(modified))
		r.Header.Set("Content-Length", fmt.Sprint(len(modified)))

	case isBuildPath(path):
		i.injectBuildLabels(r.URL)

	case isCollectionListPath(path) || isPrunePath(path):
		i.injectFilters(r.URL)
	}
}

// CheckAccess verifies that a resource targeted by the request belongs to
// this isolation context.  It makes an additional API call to the Docker
// daemon to inspect the resource.
//
// For exec instances, it resolves the parent container first.
//
// Returns nil when access is granted, or an error describing why it was denied.
func (i *Isolation) CheckAccess(ctx context.Context, dockerClient *http.Client, path string) error {
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// injectBodyLabels adds the isolation label to a JSON request body.
func (i *Isolation) injectBodyLabels(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return body
	}
	var data map[string]interface{}
	if err := json.Unmarshal(trimmed, &data); err != nil {
		return body // not JSON – leave unchanged
	}
	labels, _ := data["Labels"].(map[string]interface{})
	if labels == nil {
		labels = make(map[string]interface{})
		data["Labels"] = labels
	}
	labels[LabelKey] = i.Name
	modified, err := json.Marshal(data)
	if err != nil {
		return body
	}
	return modified
}

// injectFilters adds a label filter to the "filters" query parameter.
func (i *Isolation) injectFilters(u *url.URL) {
	q := u.Query()
	filtersStr := q.Get("filters")
	var filters map[string]interface{}
	if filtersStr != "" {
		json.Unmarshal([]byte(filtersStr), &filters)
	}
	if filters == nil {
		filters = make(map[string]interface{})
	}
	labelFilters, _ := filters["label"].(map[string]interface{})
	if labelFilters == nil {
		labelFilters = make(map[string]interface{})
		filters["label"] = labelFilters
	}
	for k, v := range i.labelFilterEntry() {
		labelFilters[k] = v
	}
	encoded, _ := json.Marshal(filters)
	q.Set("filters", string(encoded))
	u.RawQuery = q.Encode()
}

// injectBuildLabels adds the isolation label to the "labels" query parameter
// used by the Docker build API.
func (i *Isolation) injectBuildLabels(u *url.URL) {
	q := u.Query()
	labelsStr := q.Get("labels")
	var labels map[string]interface{}
	if labelsStr != "" {
		json.Unmarshal([]byte(labelsStr), &labels)
	}
	if labels == nil {
		labels = make(map[string]interface{})
	}
	labels[LabelKey] = i.Name
	encoded, _ := json.Marshal(labels)
	q.Set("labels", string(encoded))
	u.RawQuery = q.Encode()
}

// checkResource inspects a Docker resource and verifies it carries the
// isolation label.
func (i *Isolation) checkResource(ctx context.Context, client *http.Client, rt ResourceType, id string) (bool, string, error) {
	var inspectPath string
	switch rt {
	case ResourceContainer:
		inspectPath = "/containers/" + id + "/json"
	case ResourceImage:
		inspectPath = "/images/" + id + "/json"
	case ResourceVolume:
		inspectPath = "/volumes/" + id
	case ResourceNetwork:
		inspectPath = "/networks/" + id
	default:
		return false, "", fmt.Errorf("unsupported resource type %v", rt)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker"+inspectPath, nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("inspect %s: %w", inspectPath, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return false, "resource not found", nil
	case http.StatusOK:
		// proceed
	default:
		return false, "", fmt.Errorf("inspect %s returned HTTP %d", inspectPath, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("read inspect body: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return false, "", fmt.Errorf("parse inspect response: %w", err)
	}

	// Docker resources store labels in different places:
	//   - Containers: .Config.Labels
	//   - Volumes:    top-level .Labels
	//   - Networks:   top-level .Labels
	//   - Images:     .Config.Labels (but labels are set at build time only)
	var labels map[string]interface{}
	if cfg, ok := data["Config"].(map[string]interface{}); ok {
		labels, _ = cfg["Labels"].(map[string]interface{})
	} else if l, ok := data["Labels"].(map[string]interface{}); ok {
		labels = l
	}

	if labels == nil {
		return false, fmt.Sprintf("resource lacks isolation label %s=%s", LabelKey, i.Name), nil
	}

	val, ok := labels[LabelKey]
	if !ok || fmt.Sprint(val) != i.Name {
		return false, fmt.Sprintf("resource lacks isolation label %s=%s", LabelKey, i.Name), nil
	}
	return true, "", nil
}

// checkExecContainer inspects an exec instance to find its parent container,
// then checks that container for the isolation label.
func (i *Isolation) checkExecContainer(ctx context.Context, client *http.Client, execID string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/exec/"+execID+"/json", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("inspect exec %s: %w", execID, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("exec instance %s not found", execID)
	case http.StatusOK:
		// proceed
	default:
		return fmt.Errorf("inspect exec %s returned HTTP %d", execID, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read exec body: %w", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("parse exec response: %w", err)
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
	return fmt.Sprintf("isolation=%s", i.Name)
}