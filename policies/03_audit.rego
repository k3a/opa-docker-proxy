package policies

# ---------------------------------------------------------------------------
# Audit-tier policy.
#
# Operators are allowed to:
#   - inspect any resource
#   - list containers / images / volumes / networks
#   - view logs and stats
#
# Mutations (POST, PUT, DELETE on /containers/*, /images/*, …) are denied.
# ---------------------------------------------------------------------------

# Allow reading resource metadata.
allow if {
    input.method == "GET"
}

# Allow HEAD requests.
allow if {
    input.method == "HEAD"
}

# Allow listing resources.
allow if {
    input.method == "GET"
    startswith(input.path, "/v1.")
}

# Allow viewing container logs.
allow if {
    input.method == "GET"
    glob.match("/containers/*/logs", ["/"], input.path)
}

# Allow viewing container stats.
allow if {
    input.method == "GET"
    glob.match("/containers/*/stats", ["/"], input.path)
}

# Provide a clear reason when denied.
reason = "read-only audit mode — mutations are not allowed" {
    not allow
    #input.method != "GET"
    #input.method != "HEAD"
}
