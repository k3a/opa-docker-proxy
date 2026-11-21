package policies

# ============================================================================
# Operation allowlist.
#
# Default: only read-only requests (GET/HEAD) are permitted, except for
# sensitive reads (secrets, configs, swarm unlock key) and websocket attach
# (which can write to stdin).
#
# Everything else is a "write operation group" that must be enabled by name
# in `policy.allow`. Enabled operations are still subject to every denial
# rule, e.g. container creation is still hardened (02_container_security).
#
# Extra policy files may add further `request_permitted if { ... }` bodies.
# ============================================================================

write_methods := {"POST", "PUT", "DELETE", "PATCH"}

operation_groups := {
	"containers_create": [{"methods": {"POST"}, "path": `^/containers/create$`}],
	"containers_control": [
		{"methods": {"POST"}, "path": `^/containers/[^/]+/(start|stop|restart|kill|pause|unpause|wait|resize|attach|rename|update)$`},
		{"methods": {"GET"}, "path": `^/containers/[^/]+/attach/ws$`},
	],
	"containers_delete": [
		{"methods": {"DELETE"}, "path": `^/containers/[^/]+$`},
		{"methods": {"POST"}, "path": `^/containers/prune$`},
	],
	"exec": [
		{"methods": {"POST"}, "path": `^/containers/[^/]+/exec$`},
		{"methods": {"POST"}, "path": `^/exec/[^/]+/(start|resize)$`},
	],
	"build": [{"methods": {"POST"}, "path": `^/(build|build/prune|session|grpc)$`}],
	"images_pull": [{"methods": {"POST"}, "path": `^/images/create$`}],
	"images_write": [
		{"methods": {"POST"}, "path": `^/(commit|images/load|images/prune|images/.+/(tag|push))$`},
		{"methods": {"DELETE"}, "path": `^/images/.+$`},
	],
	"volumes_write": [{"methods": write_methods, "path": `^/volumes(/.*)?$`}],
	"networks_write": [{"methods": write_methods, "path": `^/networks(/.*)?$`}],
}

read_methods := {"GET", "HEAD"}

# Reads that expose secrets.
sensitive_read if regex.match(`^/(secrets|configs)`, input.path)

sensitive_read if input.path == "/swarm/unlockkey"

# Websocket attach is a GET but can send input to the container.
attach_ws if regex.match(`^/containers/[^/]+/attach/ws$`, input.path)

# With full isolation the client must see a private daemon, so only reads of
# isolatable objects (which the proxy filters/checks by label) are visible.
# Everything else that would leak daemon-wide state (/system/df, /swarm, ...)
# is hidden.
isolated_read_path if regex.match(`^/(_ping|version|info|events)$`, input.path)

isolated_read_path if regex.match(`^/(containers|images|networks|volumes|exec)(/.*)?$`, input.path)

reads_visible if isolation_mode != "full"

reads_visible if isolated_read_path

read_only_request if {
	input.method in read_methods
	not sensitive_read
	not attach_ws
	reads_visible
}

request_permitted if read_only_request

request_permitted if {
	some group in cfg.allow
	group_matches(group)
}

request_permitted if {
	opt_in("secrets_configs_read")
	input.method in read_methods
	sensitive_read
}

group_matches(group) if {
	some rule in operation_groups[group]
	input.method in rule.methods
	regex.match(rule.path, input.path)
}

# ---------------------------------------------------------------------------
# Error message, with a hint about which token would enable the request.
# ---------------------------------------------------------------------------

hint_groups contains group if {
	some group, rules in operation_groups
	some rule in rules
	input.method in rule.methods
	regex.match(rule.path, input.path)
}

hint_groups contains "secrets_configs_read" if {
	input.method in read_methods
	sensitive_read
}

enable_hint := sprintf(" (enable with policy.allow: %s)", [concat(", ", sort(hint_groups))]) if count(hint_groups) > 0

default enable_hint := ""

not_permitted_message := sprintf("%s %s is not available in isolated mode", [input.method, input.path]) if {
	input.method in read_methods
	not sensitive_read
	not attach_ws
	not reads_visible
} else := sprintf("%s %s is not permitted: only read-only requests are allowed by default%s", [input.method, input.path, enable_hint])
