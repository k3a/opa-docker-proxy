package policies

# ============================================================================
# Container creation hardening.
#
# These rules are always on. Each can be relaxed only through the policy
# config (token in `policy.allow`, or the `allowed_*` lists) — there is no
# other way to override them.
# ============================================================================

is_container_create if input.path == "/containers/create"

# The rules below inspect the parsed body. The proxy only parses bodies sent
# as application/json, so refuse anything else rather than let it skip checks.
denial contains "container creation requires a JSON object body (Content-Type: application/json)" if {
	is_container_create
	not is_object(input.body)
}

# ---------------------------------------------------------------------------
# Privileged mode and host namespaces
# ---------------------------------------------------------------------------

denial contains "privileged containers are not allowed (enable with policy.allow: privileged)" if {
	is_container_create
	input.body.HostConfig.Privileged == true
	not opt_in("privileged")
}

denial contains "host network mode is not allowed (enable with policy.allow: host_network)" if {
	is_container_create
	input.body.HostConfig.NetworkMode == "host"
	not opt_in("host_network")
}

denial contains "host PID namespace is not allowed (enable with policy.allow: host_pid)" if {
	is_container_create
	input.body.HostConfig.PidMode == "host"
	not opt_in("host_pid")
}

denial contains "host IPC namespace is not allowed (enable with policy.allow: host_ipc)" if {
	is_container_create
	input.body.HostConfig.IpcMode == "host"
	not opt_in("host_ipc")
}

denial contains "host user namespace mode is not allowed (enable with policy.allow: host_userns)" if {
	is_container_create
	input.body.HostConfig.UsernsMode == "host"
	not opt_in("host_userns")
}

# ---------------------------------------------------------------------------
# Host devices and disabled confinement
# ---------------------------------------------------------------------------

denial contains "host devices are not allowed (enable with policy.allow: devices)" if {
	is_container_create
	count(input.body.HostConfig.Devices) > 0
	not opt_in("devices")
}

# DeviceCgroupRules such as "b *:* rwm" let the container mknod and use any
# host device (MKNOD is in the default capability set). DeviceRequests asks
# device drivers (e.g. GPUs) to inject host devices.
denial contains "device cgroup rules are not allowed (enable with policy.allow: devices)" if {
	is_container_create
	count(input.body.HostConfig.DeviceCgroupRules) > 0
	not opt_in("devices")
}

denial contains "device requests are not allowed (enable with policy.allow: devices)" if {
	is_container_create
	count(input.body.HostConfig.DeviceRequests) > 0
	not opt_in("devices")
}

denial contains "unconfined security options are not allowed (enable with policy.allow: unconfined_security)" if {
	is_container_create
	some opt in input.body.HostConfig.SecurityOpt
	unconfined_option(opt)
	not opt_in("unconfined_security")
}

# MaskedPaths/ReadonlyPaths override the default /proc and /sys protections
# (what `--security-opt systempaths=unconfined` sets), so any explicit value
# (including []) is treated as unconfined.
denial contains "MaskedPaths/ReadonlyPaths overrides are not allowed (enable with policy.allow: unconfined_security)" if {
	is_container_create
	some key in {"MaskedPaths", "ReadonlyPaths"}
	input.body.HostConfig[key] != null
	not opt_in("unconfined_security")
}

unconfined_option(opt) if contains(lower(opt), "unconfined")

unconfined_option(opt) if lower(opt) in {"label=disable", "label:disable"}

# ---------------------------------------------------------------------------
# Exec
# ---------------------------------------------------------------------------

# A privileged exec runs with all capabilities and no seccomp/AppArmor,
# regardless of how the container was created.
denial contains "privileged exec is not allowed (enable with policy.allow: privileged)" if {
	regex.match(`^/containers/[^/]+/exec$`, input.path)
	input.body.Privileged == true
	not opt_in("privileged")
}

# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------

dangerous_capabilities := {
	"ALL",
	"BPF",
	"DAC_READ_SEARCH",
	"MAC_ADMIN",
	"MAC_OVERRIDE",
	"NET_ADMIN",
	"PERFMON",
	"SYS_ADMIN",
	"SYS_BOOT",
	"SYS_MODULE",
	"SYS_PTRACE",
	"SYS_RAWIO",
	"SYS_TIME",
}

# Docker accepts "net_admin", "NET_ADMIN" and "CAP_NET_ADMIN" alike.
normalize_cap(c) := trim_prefix(upper(c), "CAP_")

allowed_capabilities := {normalize_cap(c) | some c in cfg.allowed_capabilities}

denial contains sprintf("adding Linux capability %s is not allowed (enable with policy.allowed_capabilities)", [name]) if {
	is_container_create
	some cap in input.body.HostConfig.CapAdd
	name := normalize_cap(cap)
	name in dangerous_capabilities
	not name in allowed_capabilities
}

# ---------------------------------------------------------------------------
# Mounts
# ---------------------------------------------------------------------------

known_mount_types := {"bind", "volume", "tmpfs", "image", "npipe", "cluster"}

denial contains sprintf("mount type %q is not supported", [t]) if {
	is_container_create
	some mount in input.body.HostConfig.Mounts
	t := object.get(mount, "Type", "")
	not t in known_mount_types
}

# A "volume" mount with driver options can bind arbitrary host paths
# (local driver: type=none, o=bind, device=/...), bypassing the bind checks.
denial contains "volume mounts with driver options are not allowed" if {
	is_container_create
	some mount in input.body.HostConfig.Mounts
	mount.Type == "volume"
	count(mount.VolumeOptions.DriverConfig.Options) > 0
}

# Host paths bound into the container, from the Mounts and legacy Binds API.
bind_sources contains src if {
	some mount in input.body.HostConfig.Mounts
	mount.Type == "bind"
	src := object.get(mount, "Source", "")
}

# Binds entries are "<src>:<dst>[:<opts>]". A source that is a valid volume
# name is a named volume; anything else is treated as a host path. A single
# element ("/dst") is an anonymous volume.
bind_sources contains src if {
	some entry in input.body.HostConfig.Binds
	parts := split(entry, ":")
	count(parts) >= 2
	src := parts[0]
	not regex.match(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`, src)
}

denial contains sprintf("bind mount of host path %q is not allowed (enable with policy.allowed_bind_prefixes)", [src]) if {
	is_container_create
	some src in bind_sources
	not bind_source_allowed(src)
}

bind_source_allowed(src) if {
	not has_dotdot(src)
	some prefix in cfg.allowed_bind_prefixes
	startswith(src, prefix)
}

# VolumesFrom inherits another container's mounts, including host bind mounts,
# bypassing allowed_bind_prefixes. With full isolation the source must be a
# container created through the proxy, whose mounts were already checked.
denial contains "VolumesFrom is not allowed without full isolation (enable with policy.allow: volumes_from)" if {
	is_container_create
	count(input.body.HostConfig.VolumesFrom) > 0
	isolation_mode != "full"
	not opt_in("volumes_from")
}

# ---------------------------------------------------------------------------
# Volume creation
# ---------------------------------------------------------------------------

# The local driver turns DriverOpts {type: none, o: bind, device: /} into a
# bind mount of any host path, which containers then use as a plain named
# volume, bypassing allowed_bind_prefixes. Plugin drivers are opaque too.
denial contains "volume creation requires a JSON object body (Content-Type: application/json)" if {
	input.path == "/volumes/create"
	not is_object(input.body)
}

denial contains "volume driver options are not allowed" if {
	input.path == "/volumes/create"
	count(input.body.DriverOpts) > 0
}

denial contains "volume drivers other than \"local\" are not allowed" if {
	input.path == "/volumes/create"
	driver := input.body.Driver
	not driver in {"", "local"}
}

denial contains "volume driver must be a string" if {
	input.path == "/volumes/create"
	input.body.Driver
	not is_string(input.body.Driver)
}
