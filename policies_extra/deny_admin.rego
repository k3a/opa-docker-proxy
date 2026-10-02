package policies

# ============================================================================
# Disable admin-style operations
# ---------------------------------------------------------------------------

denial contains "container lifecycle operations are denied" if {
	regex.match("^/containers/[^/]+/(start|stop|restart|kill|pause|unpause|rename|update)$", input.path)
}

denial contains "creation of containers is denied" if {
	input.path == "/containers/create"
}

denial contains "delete operations are denied" if {
	input.method == "DELETE"
}
