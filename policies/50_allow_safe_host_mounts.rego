package policies

# ============================================================================
# Allow host mounts to safe paths.
#
# Overrides the blanket block-bind-mounts rule from 02_container_security.rego
# when the host source path starts with one of the permitted prefixes:
#   - /dev/
#   - /temp/agent/
#
# Supports both the structured Mounts API (HostConfig.Mounts) and the legacy
# Binds API (HostConfig.Binds). Bind/mount sources must not contain ".." as a
# path component to prevent path traversal attacks.
#
# IMPORTANT: This rule still respects all other security denials (privileged
# containers, capabilities, host network, etc.). It only overrides the
# specific bind-mount and container-creation denials when the bind sources
# are all on allowed paths with no ".." traversal.
# ============================================================================

# ---------------------------------------------------------------------------
# Permit container creation when the only denials present are the ones this
# rule is designed to override (bind-mount and container-creation), AND all
# bind sources use allowed host paths without ".." path traversal.
# ---------------------------------------------------------------------------
allow if {
	input.path == "/containers/create"

	# At least one bind mount exists in either Mounts or Binds.
	some source in all_bind_sources

	# Every bind source must start with an allowed prefix.
	not any_disallowed_bind_source(all_bind_sources)

	# No bind source may contain ".." as a path component (path traversal).
	not any_dotdot_in_bind_sources

	# No non-overridable denials exist — other security rules are enforced.
	not non_bind_mount_denial_exists
}

# ---------------------------------------------------------------------------
# all_bind_sources collects host source paths from both the Mounts array and
# the legacy Binds array.  (Sources are NOT filtered here — the ".." check
# is done separately via any_dotdot_in_bind_sources so that any single
# offending source causes a full denial.)
# ---------------------------------------------------------------------------
all_bind_sources contains source if {
	some mount in input.body.HostConfig.Mounts
	mount.Type == "bind"
	source := mount.Source
}

all_bind_sources contains source if {
	some entry in input.body.HostConfig.Binds
	source := bind_source_from_entry(entry)
}

# ---------------------------------------------------------------------------
# bind_source_from_entry extracts the host source path from a legacy Binds
# entry of the form "<src>:<dst>[:<options>]".
# ---------------------------------------------------------------------------
bind_source_from_entry(entry) := src if {
	parts := split(entry, ":")
	src := parts[0]
}

# ---------------------------------------------------------------------------
# any_dotdot_in_bind_sources is true when ANY bind source contains ".." as a
# path component, indicating a path traversal attempt.  This matches ".."
# at the start of a path, in the middle between slashes, or at the end.
#
# Pattern:  (^|/)\.\.(/|$)
#   (^|/)  – start of string or a slash
#   \.\.   – literal ".."
#   (/|$)  – a slash or end of string
# ---------------------------------------------------------------------------
any_dotdot_in_bind_sources if {
	some source in all_bind_sources
	regex.match("(^|/)\\.\\.(/|$)", source)
}

# ---------------------------------------------------------------------------
# any_disallowed_bind_source is true when at least one bind source references
# a host source path that is not in the allowed set.
# ---------------------------------------------------------------------------
any_disallowed_bind_source(sources) if {
	some source in sources
	not startswith(source, "/dev/")
	not startswith(source, "/temp/agent/")
}

# ---------------------------------------------------------------------------
# non_bind_mount_denial_exists is true when the denial set contains any
# message that is not overridden by this rule — i.e., a separate security
# policy was violated beyond the ones this rule is designed to permit.
#
# Overridden denials:
#   - "bind mounts are not allowed"       (02_container_security.rego)
#
# Any other denial message still blocks the request.
# ---------------------------------------------------------------------------
non_bind_mount_denial_exists if {
	msg := denial[_]
	msg != "bind mounts are not allowed"
}
