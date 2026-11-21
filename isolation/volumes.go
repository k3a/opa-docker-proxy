package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
)

// checkCreate handles /containers/create:
//
//  1. every referenced resource (image, networks, volumes, containers) must
//     not belong to another isolation context;
//  2. named volumes that do not exist yet are created up front with the
//     isolation label (the daemon would create them implicitly, unlabelled);
//  3. anonymous volumes (single-element Binds, "Volumes", and volumes declared
//     by the image) are turned into labelled volume mounts.
func (i *Isolation) checkCreate(ctx context.Context, client *http.Client, r *http.Request) error {
	data, ok, err := readJSONBody(r)
	if err != nil || !ok {
		return err
	}

	missing, err := i.checkRefs(ctx, client, createReferences(data))
	if err != nil {
		return err
	}

	for _, ref := range missing {
		if ref.typ != ResourceVolume || ref.noCreate {
			continue
		}

		if err := i.createVolume(ctx, client, ref.id); err != nil {
			return err
		}
	}

	changed, err := i.labelAnonymousVolumes(ctx, client, data)
	if err != nil {
		return err
	}

	if changed {
		out, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}

		setBody(r, out)
	}

	return nil
}

// createVolume creates a labelled volume. If the name was taken in the
// meantime, Docker returns the existing volume, which must then be ours.
func (i *Isolation) createVolume(ctx context.Context, client *http.Client, name string) error {
	payload, _ := json.Marshal(map[string]any{"Name": name, "Labels": map[string]any{LabelKey: i.Name}})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/volumes/create", bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("create volume %q: %w", name, err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close volume create body", "error", err)
		}
	}()

	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

		return fmt.Errorf("create volume %q: HTTP %d: %s", name, resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	st, err := i.ownership(ctx, client, ResourceVolume, name)
	if err != nil {
		return err
	}

	if st != owned {
		return fmt.Errorf("access denied: volume %q belongs to another isolation context", name)
	}

	return nil
}

// mountTargets returns the container paths already used by explicit mounts.
func mountTargets(hc map[string]any) map[string]bool {
	used := map[string]bool{}

	for _, m := range objects(lookup(hc, "Mounts")) {
		for _, t := range strs(lookup(m, "Target")) {
			used[t] = true
		}
	}

	for _, e := range strs(lookup(hc, "Binds")) {
		// Single-element entries are anonymous volumes; they are handled
		// (and moved to Mounts) by the caller.
		if parts := strings.Split(e, ":"); len(parts) >= 2 {
			used[parts[1]] = true
		}
	}

	for _, t := range objects(lookup(hc, "Tmpfs")) {
		for path := range t {
			used[path] = true
		}
	}

	return used
}

// labelAnonymousVolumes rewrites anonymous volumes into volume mounts that
// carry the isolation label, so they can be attributed (and cleaned up by
// label-scoped prune). Returns whether the body changed.
//
// Skipped when VolumesFrom is used: the inherited mount points are unknown
// and a duplicate target would make the daemon reject the request.
func (i *Isolation) labelAnonymousVolumes(ctx context.Context, client *http.Client, data map[string]any) (bool, error) {
	if len(strs(lookup(mergeObjects(data, "HostConfig"), "VolumesFrom"))) > 0 {
		return false, nil
	}

	hc := mergeObjects(data, "HostConfig")
	used := mountTargets(hc)

	targets := map[string]bool{}

	// Single-element Binds ("/data") are anonymous volumes.
	var keep []any

	removed := false

	for _, e := range strs(lookup(hc, "Binds")) {
		if !strings.Contains(e, ":") && strings.HasPrefix(e, "/") {
			targets[e] = true
			removed = true

			continue
		}

		keep = append(keep, e)
	}

	if removed {
		for k := range hc {
			if strings.EqualFold(k, "Binds") {
				delete(hc, k)
			}
		}

		hc["Binds"] = keep
	}

	// Container config "Volumes".
	for _, v := range objects(lookup(data, "Volumes")) {
		for path := range v {
			targets[path] = true
		}
	}

	// Volumes declared by the image (Dockerfile VOLUME).
	for _, img := range strs(lookup(data, "Image")) {
		imgData, found, err := inspectJSON(ctx, client, "/images/"+escapeRef(img)+"/json")
		if err != nil {
			return false, fmt.Errorf("inspect image %q: %w", img, err)
		}

		if !found {
			continue
		}

		cfg, _ := imgData["Config"].(map[string]any)

		vols, _ := cfg["Volumes"].(map[string]any)
		for path := range vols {
			targets[path] = true
		}
	}

	var paths []string

	for t := range targets {
		if !used[t] {
			paths = append(paths, t)
		}
	}

	if len(paths) == 0 {
		return removed, nil
	}

	sort.Strings(paths)

	mounts := make([]any, 0, len(paths))

	for _, m := range objects(lookup(hc, "Mounts")) {
		mounts = append(mounts, m)
	}

	for _, t := range paths {
		mounts = append(mounts, map[string]any{
			"Type":          "volume",
			"Target":        t,
			"VolumeOptions": map[string]any{"Labels": map[string]any{LabelKey: i.Name}},
		})
	}

	for k := range hc {
		if strings.EqualFold(k, "Mounts") {
			delete(hc, k)
		}
	}

	hc["Mounts"] = mounts

	return true, nil
}
