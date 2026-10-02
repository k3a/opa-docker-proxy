package policies

# ============================================================================
# Container creation restrictions.
# ============================================================================

# ---------------------------------------------------------------------------
# block-capability-escalation
# Prevent containers from requesting dangerous Linux capabilities.
# ---------------------------------------------------------------------------
denial contains "adding privileged Linux capabilities is not allowed" if {
    input.path == "/containers/create"
    some cap in input.body.HostConfig.CapAdd
    cap in {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"}
}

# ---------------------------------------------------------------------------
# block-privileged
# Prevent privileged containers.
# ---------------------------------------------------------------------------
denial contains "privileged containers are not allowed" if {
	input.path == "/containers/create"
	input.body.HostConfig.Privileged == true
}

# ---------------------------------------------------------------------------
# block-host-network
# Prevent containers from using host network mode.
# ---------------------------------------------------------------------------
denial contains "host network mode is not allowed" if {
	input.path == "/containers/create"
	input.body.HostConfig.NetworkMode == "host"
}

# ---------------------------------------------------------------------------
# block-host-pid
# Prevent containers from using host PID namespace.
# ---------------------------------------------------------------------------
denial contains "host PID namespace is not allowed" if {
	input.path == "/containers/create"
	input.body.HostConfig.PidMode == "host"
}

# ---------------------------------------------------------------------------
# block-host-userns
# Prevent containers from using host user namespace.
# ---------------------------------------------------------------------------
denial contains "host user namespace mode is not allowed" if {
	input.path == "/containers/create"
	input.body.HostConfig.UsernsMode == "host"
}

# ---------------------------------------------------------------------------
# block-bind-mounts
# Prevent bind mounts via either the Binds array or the Mounts array.
# ---------------------------------------------------------------------------

# Deny if the legacy Binds field exists (even if empty — existence is enough).
denial contains "bind mounts are not allowed" if {
        input.path == "/containers/create"
        input.body.HostConfig.Binds != null
        print("bind mounts not allowed", input.body.HostConfig.Binds)
}

# Deny if any entry in the Mounts array has Type == "bind".
denial contains $"bind mounts are not allowed: {input.body.HostConfig.Mounts}" if {
        input.path == "/containers/create"
        mount := input.body.HostConfig.Mounts[_]
        mount.Type == "bind"
        print("bind mounts not allowed", mount)
}
