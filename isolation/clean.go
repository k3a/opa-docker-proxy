package isolation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// CleanResult counts what Clean removed and lists what it failed to remove.
type CleanResult struct {
	Removed  map[ResourceType]int
	Failures []string
}

// Clean removes every container, network, volume and image carrying the
// isolation label, talking to the Docker daemon directly (not through the
// proxy). With all false only objects labelled with this isolation's name are
// removed; with all true every object carrying the label key, whatever its
// value, is removed. progress, when non-nil, is called for each removed object.
//
// Objects are removed in dependency order (containers, networks, volumes,
// images). Individual failures are collected in the result and do not stop
// the run; an error is returned only when listing fails.
func Clean(ctx context.Context, client *http.Client, name string, all bool, progress func(ResourceType, string)) (CleanResult, error) {
	label := LabelKey
	if !all {
		label += "=" + name
	}

	filters, err := json.Marshal(map[string][]string{"label": {label}})
	if err != nil {
		return CleanResult{}, err
	}

	res := CleanResult{Removed: map[ResourceType]int{}}

	steps := []struct {
		typ    ResourceType
		list   string
		query  string
		ids    func(body []byte) ([]string, error)
		remove func(id string) string
	}{
		{ResourceContainer, "/containers/json", "all=1", func(b []byte) ([]string, error) {
			return idsOf(b, "Id")
		}, func(id string) string { return "/containers/" + url.PathEscape(id) + "?force=1" }},
		{ResourceNetwork, "/networks", "", func(b []byte) ([]string, error) {
			return idsOf(b, "Id")
		}, func(id string) string { return "/networks/" + url.PathEscape(id) }},
		{ResourceVolume, "/volumes", "", func(b []byte) ([]string, error) {
			var v struct{ Volumes []struct{ Name string } }
			if err := json.Unmarshal(b, &v); err != nil {
				return nil, err
			}

			out := make([]string, 0, len(v.Volumes))
			for _, vol := range v.Volumes {
				out = append(out, vol.Name)
			}

			return out, nil
		}, func(id string) string { return "/volumes/" + url.PathEscape(id) + "?force=1" }},
		{ResourceImage, "/images/json", "", func(b []byte) ([]string, error) {
			return idsOf(b, "Id")
		}, func(id string) string { return "/images/" + url.PathEscape(id) + "?force=1" }},
	}

	for _, s := range steps {
		q := url.Values{"filters": {string(filters)}}
		if s.query != "" {
			q.Set("all", "1")
		}

		body, status, err := dockerDo(ctx, client, http.MethodGet, s.list+"?"+q.Encode())
		if err != nil {
			return res, fmt.Errorf("list %v: %w", s.typ, err)
		}

		if status != http.StatusOK {
			return res, fmt.Errorf("list %v: HTTP %d: %s", s.typ, status, body)
		}

		ids, err := s.ids(body)
		if err != nil {
			return res, fmt.Errorf("parse %v list: %w", s.typ, err)
		}

		for _, id := range ids {
			body, status, err := dockerDo(ctx, client, http.MethodDelete, s.remove(id))

			switch {
			case err != nil:
				res.Failures = append(res.Failures, fmt.Sprintf("%v %s: %v", s.typ, id, err))
			case status != http.StatusNoContent && status != http.StatusOK && status != http.StatusNotFound:
				res.Failures = append(res.Failures, fmt.Sprintf("%v %s: HTTP %d: %s", s.typ, id, status, body))
			default:
				res.Removed[s.typ]++

				if progress != nil {
					progress(s.typ, id)
				}
			}
		}
	}

	return res, nil
}

func idsOf(body []byte, key string) ([]string, error) {
	var items []map[string]any
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(items))

	for _, it := range items {
		if id, ok := it[key].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}

	return ids, nil
}

func dockerDo(ctx context.Context, client *http.Client, method, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return nil, 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	return body, resp.StatusCode, err
}
