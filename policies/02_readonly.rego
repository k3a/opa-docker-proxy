package policies

# ---------------------------------------------------------------------------
# Read-only mode: allow GET and HEAD requests to any path.
# ---------------------------------------------------------------------------
allow if {
    input.method == "GET"
}

allow if {
    input.method == "HEAD"
}