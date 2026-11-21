package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/k3a/opa-docker-proxy/utils"
)

// escapeRef escapes an image reference for use in a path. Image names contain
// slashes, which must stay path separators.
func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for n, p := range parts {
		parts[n] = url.PathEscape(p)
	}

	return strings.Join(parts, "/")
}

// imageTarget extracts the image a /images/... request addresses. write is
// true for requests that change the image (delete, push, tag).
// ok is false for collection endpoints (list, pull, load, prune, search, get).
func imageTarget(cleaned, method string) (name string, write, ok bool) {
	rest, found := strings.CutPrefix(cleaned, "/images/")
	if !found || rest == "" {
		return "", false, false
	}

	switch rest {
	case "json", "create", "load", "prune", "search", "get":
		return "", false, false
	}

	for _, suffix := range []string{"/json", "/history", "/get"} {
		if n, cut := strings.CutSuffix(rest, suffix); cut && n != "" {
			return n, false, true
		}
	}

	for _, suffix := range []string{"/push", "/tag"} {
		if n, cut := strings.CutSuffix(rest, suffix); cut && n != "" {
			return n, true, true
		}
	}

	return rest, method == http.MethodDelete, true
}

// checkImage enforces the image rules: foreign images are off limits; shared
// (unlabelled) images are usable but read-only; own images are fully usable.
// Missing images are left to the daemon.
func (i *Isolation) checkImage(ctx context.Context, client *http.Client, name string, write bool) error {
	st, err := i.ownership(ctx, client, ResourceImage, name)
	if err != nil {
		return fmt.Errorf("isolation check for image %s: %w", name, err)
	}

	switch {
	case st == foreign:
		return fmt.Errorf("access denied: image %q belongs to another isolation context", name)
	case st == hidden:
		return fmt.Errorf("access denied: image %q is not permitted (policy.allowed_images)", name)
	case st == shared && write:
		return fmt.Errorf("access denied: image %q is shared (not created through this proxy) and can not be changed", name)
	}

	return nil
}

// withTag combines the repo and tag parameters the way the daemon does: an
// explicit tag replaces any tag or digest already in repo.
func withTag(repo, tag string) string {
	if tag == "" {
		return repo
	}

	if n, _, found := strings.Cut(repo, "@"); found {
		repo = n
	}

	if c := strings.LastIndex(repo, ":"); c > strings.LastIndex(repo, "/") {
		repo = repo[:c]
	}

	return repo + ":" + tag
}

var imageTagPath = regexp.MustCompile(`^/images/.+/tag$`)

// destinationRefs lists the image names a request writes to (tag, commit,
// build) and reports whether the request creates an image that can not be
// labelled and must be denied (load, import).
func destinationRefs(r *http.Request, cleaned string) (refs []string, denied string) {
	if r.Method != http.MethodPost {
		return nil, ""
	}

	q := r.URL.Query()

	switch {
	case cleaned == "/images/load":
		return nil, "loading images is not allowed with isolation (the image can not be labelled)"
	case cleaned == "/images/create" && q.Has("fromSrc"):
		return nil, "importing images is not allowed with isolation (the image can not be labelled)"
	case cleaned == "/commit" || imageTagPath.MatchString(cleaned):
		if repo := q.Get("repo"); repo != "" {
			refs = append(refs, withTag(repo, q.Get("tag")))
		}
	case cleaned == "/build":
		refs = append(refs, q["t"]...)
	}

	return refs, ""
}

// checkDestinations denies requests that would move a name onto a shared or
// foreign image. Names that do not exist yet, and own images, are fine.
func (i *Isolation) checkDestinations(ctx context.Context, client *http.Client, r *http.Request) error {
	refs, denied := destinationRefs(r, utils.StripVersionPrefix(r.URL.Path))
	if denied != "" {
		return errors.New("access denied: " + denied)
	}

	for _, ref := range refs {
		if err := i.checkImage(ctx, client, ref, true); err != nil {
			return fmt.Errorf("image name %q can not be written: %w", ref, err)
		}
	}

	return nil
}

// imageRefs lists the references of an inspected/listed image: the name used
// plus its repo tags and digests.
func imageRefs(used string, data map[string]any) []string {
	refs := []string{}
	if used != "" {
		refs = append(refs, used)
	}

	for _, key := range []string{"RepoTags", "RepoDigests"} {
		for _, v := range strs([]any{data[key]}) {
			refs = append(refs, v)
		}
	}

	return refs
}

// FilterResponse hides images from image lists (full mode only): images of
// other isolation contexts, and shared (unlabelled) images that
// policy.allowed_images does not permit. Own images always stay visible. It is
// meant to be called from the reverse proxy's ModifyResponse.
func (i *Isolation) FilterResponse(resp *http.Response) error {
	req := resp.Request
	if i.Mode != ModeFull || req == nil || req.Method != http.MethodGet ||
		utils.StripVersionPrefix(req.URL.Path) != "/images/json" ||
		resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read image list: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("close image list: %w", err)
	}

	var images []map[string]any
	if err := json.Unmarshal(body, &images); err != nil {
		// Unknown shape: fail closed rather than leak the list.
		return fmt.Errorf("parse image list: %w", err)
	}

	visible := make([]map[string]any, 0, len(images))

	for _, img := range images {
		labels, _ := img["Labels"].(map[string]any)

		v, labelled := labels[LabelKey]

		switch {
		case labelled && fmt.Sprint(v) != i.Name:
			continue // another context's image
		case !labelled && i.ImageVisible != nil && !i.ImageVisible(imageRefs("", img)):
			continue // shared image the allowlist does not permit
		}

		visible = append(visible, img)
	}

	out, err := json.Marshal(visible)
	if err != nil {
		return fmt.Errorf("encode image list: %w", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))

	return nil
}
