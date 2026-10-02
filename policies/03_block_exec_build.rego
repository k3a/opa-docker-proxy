package policies

# ============================================================================
# Block dangerous operations.
# ============================================================================

# ---------------------------------------------------------------------------
# block-exec
# Prevent container exec and exec start operations.
# Matches paths like:
#   /containers/{id}/exec
#   /exec/{id}/start
# ---------------------------------------------------------------------------
denial contains "exec operations are not permitted" if {
	regex.match("^/containers/[^/]+/exec$", input.path)
}

denial contains "exec operations are not permitted" if {
	regex.match("^/exec/[^/]+/start$", input.path)
}

# ---------------------------------------------------------------------------
# block-build
# Prevent image building.
# ---------------------------------------------------------------------------
denial contains "image building is not permitted" if {
	startswith(input.path, "/build")
}
