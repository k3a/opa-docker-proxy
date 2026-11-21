// Package utils provides utility functions for URL path processing.
package utils

import "strings"

// ---------------------------------------------------------------------------
// URL path helpers – determine what kind of Docker API endpoint we are
// hitting.
// ---------------------------------------------------------------------------

// SplitVersionPath splits a versioned path /v1.2/x to v1.2 and /x.
// The version string will be empty if there was no version prefix in the path.
func SplitVersionPath(path string) (string, string) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) < 2 {
		return "", path
	}

	if len(parts[0]) > 0 && parts[0][0] == 'v' {
		return parts[0], "/" + parts[1]
	}

	return "", path
}

// StripVersionPrefix strips an optional /v1.xx prefix from a Docker API path.
func StripVersionPrefix(path string) string {
	_, path = SplitVersionPath(path)

	return path
}
