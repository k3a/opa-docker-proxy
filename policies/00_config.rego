package policies

# ============================================================================
# Policy configuration.
#
# The proxy loads the `policy:` section of config.yaml into `data.config`.
# User values are merged over default_config, so every knob has a safe
# default (everything dangerous or non-read-only is blocked).
#
# Invalid configuration (unknown key, wrong type, unknown token, malformed
# value) is reported in `config_errors`.  The proxy refuses to start with a
# non-empty set, and — as a second line of defence — every request is denied.
# ============================================================================

default_config := {
	# Opt-in tokens, see allow_tokens below.
	"allow": [],
	# Host path prefixes bind mounts may use. Must start and end with "/".
	"allowed_bind_prefixes": [],
	# Capabilities (without CAP_ prefix) that may be added even though they
	# are on the dangerous list.
	"allowed_capabilities": [],
	# Image reference patterns (glob, "*" matches any characters) that may be
	# pulled and run. Empty = any image. A pattern without tag ("alpine")
	# matches every tag and digest of that repository.
	"allowed_images": [],
	# Client networks allowed to talk to the proxy (Unix socket clients are
	# always allowed).
	"allowed_client_cidrs": [
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
	],
}

# Tokens accepted in `allow`.
#   operation groups (see 03_operations.rego)
#   hardening exemptions (see 02_container_security.rego)
allow_tokens := {
	"containers_create",
	"containers_control",
	"containers_delete",
	"exec",
	"build",
	"images_pull",
	"images_write",
	"volumes_write",
	"networks_write",
	"secrets_configs_read",
	"privileged",
	"host_network",
	"host_pid",
	"host_ipc",
	"host_userns",
	"devices",
	"volumes_from",
	"unconfined_security",
}

# Runtime facts supplied by the proxy (not user-configurable):
#   data.runtime.isolation.mode is "off", "full" or "writes".
default isolation_mode := "off"

isolation_mode := data.runtime.isolation.mode

default user_config := {}

user_config := data.config

cfg := object.union(default_config, user_config) if is_object(user_config)

else := default_config

# opt_in(token) is true when the user enabled the token via `allow`.
opt_in(token) if token in cfg.allow

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

config_errors contains "policy config must be an object" if not is_object(user_config)

config_errors contains sprintf("unknown policy config key %q", [k]) if {
	is_object(user_config)
	some k, _ in user_config
	not k in object.keys(default_config)
}

config_errors contains sprintf("policy.%s must be a list of strings", [k]) if {
	some k in object.keys(default_config)
	not is_string_list(cfg[k])
}

config_errors contains sprintf("unknown policy.allow entry %q (valid: %s)", [t, concat(", ", sort(allow_tokens))]) if {
	is_string_list(cfg.allow)
	some t in cfg.allow
	not t in allow_tokens
}

config_errors contains sprintf("policy.allowed_bind_prefixes entry %q must start and end with \"/\" and not contain \"..\"", [p]) if {
	is_string_list(cfg.allowed_bind_prefixes)
	some p in cfg.allowed_bind_prefixes
	not valid_bind_prefix(p)
}

config_errors contains sprintf("policy.allowed_images entry %q must not be empty", [p]) if {
	is_string_list(cfg.allowed_images)
	some p in cfg.allowed_images
	trim_space(p) == ""
}

config_errors contains sprintf("policy.allowed_client_cidrs entry %q is not a valid CIDR", [c]) if {
	is_string_list(cfg.allowed_client_cidrs)
	some c in cfg.allowed_client_cidrs
	not net.cidr_is_valid(c)
}

is_string_list(x) if {
	is_array(x)
	every e in x {
		is_string(e)
	}
}

valid_bind_prefix(p) if {
	startswith(p, "/")
	endswith(p, "/")
	not has_dotdot(p)
}

# has_dotdot is true when the path has ".." as a path component.
has_dotdot(p) if regex.match(`(^|/)\.\.(/|$)`, p)
