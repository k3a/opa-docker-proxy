package policies

# ============================================================================
# Tests. Run with: opa test policies/ -v
# ============================================================================

req(method, path) := {"method": method, "path": path, "client_ip": "@"}

create(host_config) := {
	"method": "POST",
	"path": "/containers/create",
	"client_ip": "@",
	"body": {"Image": "alpine", "HostConfig": host_config},
}

create_cfg(extra) := object.union({"allow": ["containers_create"]}, extra)

# ---------------------------------------------------------------------------
# Defaults: read-only
# ---------------------------------------------------------------------------

test_default_allows_reads if {
	allow with input as req("GET", "/containers/json") with data.config as {}
	allow with input as req("GET", "/containers/abc/logs") with data.config as {}
	allow with input as req("HEAD", "/_ping") with data.config as {}
	allow with input as req("GET", "/images/json") with data.config as {}
}

test_default_denies_all_writes if {
	some r in [
		["POST", "/containers/create"],
		["POST", "/containers/abc/start"],
		["POST", "/containers/abc/kill"],
		["DELETE", "/containers/abc"],
		["POST", "/containers/abc/exec"],
		["POST", "/exec/abc/start"],
		["POST", "/build"],
		["POST", "/images/create"],
		["DELETE", "/images/abc"],
		["POST", "/volumes/create"],
		["POST", "/networks/create"],
		["PUT", "/containers/abc/archive"],
		["POST", "/swarm/init"],
		["POST", "/plugins/pull"],
	]
	not allow with input as req(r[0], r[1]) with data.config as {}
}

test_default_denies_sensitive_reads if {
	not allow with input as req("GET", "/secrets") with data.config as {}
	not allow with input as req("GET", "/configs/abc") with data.config as {}
	not allow with input as req("GET", "/swarm/unlockkey") with data.config as {}
	not allow with input as req("GET", "/containers/abc/attach/ws") with data.config as {}
}

test_unknown_endpoint_write_denied_even_with_groups if {
	cfg := {"allow": ["containers_create", "containers_control", "containers_delete", "exec", "build", "images_write", "volumes_write", "networks_write"]}
	not allow with input as req("POST", "/swarm/init") with data.config as cfg
	not allow with input as req("PUT", "/containers/abc/archive") with data.config as cfg
	not allow with input as req("POST", "/plugins/pull") with data.config as cfg
}

test_denial_message_hints_at_token if {
	r := reason with input as req("POST", "/containers/abc/start") with data.config as {}
	contains(r, "containers_control")
}

# ---------------------------------------------------------------------------
# Operation groups
# ---------------------------------------------------------------------------

test_group_containers_control if {
	cfg := {"allow": ["containers_control"]}
	allow with input as req("POST", "/containers/abc/start") with data.config as cfg
	allow with input as req("POST", "/containers/abc/attach") with data.config as cfg
	allow with input as req("GET", "/containers/abc/attach/ws") with data.config as cfg
	not allow with input as req("POST", "/containers/create") with data.config as cfg
	not allow with input as req("DELETE", "/containers/abc") with data.config as cfg
	not allow with input as req("POST", "/containers/abc/exec") with data.config as cfg
}

test_group_containers_delete if {
	cfg := {"allow": ["containers_delete"]}
	allow with input as req("DELETE", "/containers/abc") with data.config as cfg
	allow with input as req("POST", "/containers/prune") with data.config as cfg
	not allow with input as req("DELETE", "/images/abc") with data.config as cfg
}

test_group_exec if {
	cfg := {"allow": ["exec"]}
	allow with input as req("POST", "/containers/abc/exec") with data.config as cfg
	allow with input as req("POST", "/exec/abc/start") with data.config as cfg
}

test_group_build if {
	cfg := {"allow": ["build"]}
	allow with input as req("POST", "/build") with data.config as cfg
	not allow with input as req("POST", "/images/create") with data.config as cfg
}

test_group_images_volumes_networks if {
	allow with input as req("POST", "/images/create") with data.config as {"allow": ["images_write"]}
	allow with input as req("DELETE", "/images/abc") with data.config as {"allow": ["images_write"]}
	allow with input as req("POST", "/volumes/create") with data.config as {"allow": ["volumes_write"]}
	allow with input as req("POST", "/networks/create") with data.config as {"allow": ["networks_write"]}
	not allow with input as req("POST", "/networks/create") with data.config as {"allow": ["volumes_write"]}
}

test_group_secrets_configs_read if {
	cfg := {"allow": ["secrets_configs_read"]}
	allow with input as req("GET", "/secrets") with data.config as cfg
	not allow with input as req("POST", "/secrets/create") with data.config as cfg
}

# ---------------------------------------------------------------------------
# Container creation hardening (default config + containers_create)
# ---------------------------------------------------------------------------

test_create_plain_allowed if {
	allow with input as create({}) with data.config as create_cfg({})
}

test_create_requires_json_object_body if {
	not allow with input as {"method": "POST", "path": "/containers/create", "client_ip": "@", "body": "{\"HostConfig\":{\"Privileged\":true}}"} with data.config as create_cfg({})
}

test_create_privileged_denied if {
	not allow with input as create({"Privileged": true}) with data.config as create_cfg({})
}

test_create_privileged_opt_in if {
	allow with input as create({"Privileged": true}) with data.config as {"allow": ["containers_create", "privileged"]}
}

test_create_host_namespaces_denied if {
	not allow with input as create({"NetworkMode": "host"}) with data.config as create_cfg({})
	not allow with input as create({"PidMode": "host"}) with data.config as create_cfg({})
	not allow with input as create({"IpcMode": "host"}) with data.config as create_cfg({})
	not allow with input as create({"UsernsMode": "host"}) with data.config as create_cfg({})
}

test_create_host_namespaces_opt_in if {
	allow with input as create({"NetworkMode": "host"}) with data.config as {"allow": ["containers_create", "host_network"]}
	allow with input as create({"PidMode": "host"}) with data.config as {"allow": ["containers_create", "host_pid"]}
	allow with input as create({"IpcMode": "host"}) with data.config as {"allow": ["containers_create", "host_ipc"]}
	allow with input as create({"UsernsMode": "host"}) with data.config as {"allow": ["containers_create", "host_userns"]}
}

test_create_opt_in_of_one_does_not_relax_another if {
	not allow with input as create({"Privileged": true, "NetworkMode": "host"}) with data.config as {"allow": ["containers_create", "host_network"]}
}

test_create_devices_and_unconfined if {
	not allow with input as create({"Devices": [{"PathOnHost": "/dev/sda"}]}) with data.config as create_cfg({})
	not allow with input as create({"SecurityOpt": ["seccomp=unconfined"]}) with data.config as create_cfg({})
	not allow with input as create({"SecurityOpt": ["label=disable"]}) with data.config as create_cfg({})
	allow with input as create({"SecurityOpt": ["no-new-privileges"]}) with data.config as create_cfg({})
	allow with input as create({"Devices": [{"PathOnHost": "/dev/sda"}]}) with data.config as {"allow": ["containers_create", "devices"]}
}

test_create_capabilities if {
	not allow with input as create({"CapAdd": ["SYS_ADMIN"]}) with data.config as create_cfg({})
	not allow with input as create({"CapAdd": ["ALL"]}) with data.config as create_cfg({})
	allow with input as create({"CapAdd": ["CHOWN", "NET_BIND_SERVICE"]}) with data.config as create_cfg({})
}

# Docker accepts lower case and a CAP_ prefix.
test_create_capabilities_normalized if {
	not allow with input as create({"CapAdd": ["sys_admin"]}) with data.config as create_cfg({})
	not allow with input as create({"CapAdd": ["CAP_SYS_ADMIN"]}) with data.config as create_cfg({})
	not allow with input as create({"CapAdd": ["cap_net_admin"]}) with data.config as create_cfg({})
}

test_create_capabilities_opt_in if {
	cfg := create_cfg({"allowed_capabilities": ["net_admin"]})
	allow with input as create({"CapAdd": ["CAP_NET_ADMIN"]}) with data.config as cfg
	not allow with input as create({"CapAdd": ["NET_ADMIN", "SYS_ADMIN"]}) with data.config as cfg
}

# ---------------------------------------------------------------------------
# Mounts
# ---------------------------------------------------------------------------

test_mount_non_bind_allowed if {
	allow with input as create({"Mounts": [{"Type": "volume", "Source": "v", "Target": "/v"}, {"Type": "tmpfs", "Target": "/t"}]}) with data.config as create_cfg({})
	allow with input as create({"Binds": ["myvol:/data", "/anon"], "Mounts": []}) with data.config as create_cfg({})
	allow with input as create({"Binds": []}) with data.config as create_cfg({})
}

test_mount_bind_denied_by_default if {
	not allow with input as create({"Mounts": [{"Type": "bind", "Source": "/dev/sda", "Target": "/x"}]}) with data.config as create_cfg({})
	not allow with input as create({"Binds": ["/dev/sda:/x"]}) with data.config as create_cfg({})
	not allow with input as create({"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}) with data.config as create_cfg({})
}

test_mount_bind_prefix_allowed_via_mounts if {
	cfg := create_cfg({"allowed_bind_prefixes": ["/dev/", "/temp/agent/"]})
	allow with input as create({"Mounts": [{"Type": "bind", "Source": "/dev/sda", "Target": "/x"}]}) with data.config as cfg
	allow with input as create({"Mounts": [{"Type": "bind", "Source": "/temp/agent/data", "Target": "/x"}]}) with data.config as cfg
}

test_mount_bind_prefix_allowed_via_binds if {
	cfg := create_cfg({"allowed_bind_prefixes": ["/dev/", "/temp/agent/"]})
	allow with input as create({"Binds": ["/dev/sda:/x", "/temp/agent/data:/d:ro,Z"]}) with data.config as cfg
}

test_mount_bind_one_bad_source_denies_all if {
	cfg := create_cfg({"allowed_bind_prefixes": ["/dev/"]})
	not allow with input as create({"Mounts": [{"Type": "bind", "Source": "/dev/sda", "Target": "/x"}, {"Type": "bind", "Source": "/etc", "Target": "/y"}]}) with data.config as cfg
	not allow with input as create({"Binds": ["/dev/sda:/x", "/etc:/y"]}) with data.config as cfg
	not allow with input as create({"Mounts": [{"Type": "bind", "Source": "/dev/sda", "Target": "/x"}], "Binds": ["/etc:/y"]}) with data.config as cfg
}

test_mount_bind_traversal_denied if {
	cfg := create_cfg({"allowed_bind_prefixes": ["/dev/"]})
	not allow with input as create({"Mounts": [{"Type": "bind", "Source": "/dev/../etc", "Target": "/x"}]}) with data.config as cfg
	not allow with input as create({"Binds": ["/dev/../etc:/x"]}) with data.config as cfg
	not allow with input as create({"Binds": ["/dev/..:/x"]}) with data.config as cfg
	not allow with input as create({"Binds": ["../dev/x:/x"]}) with data.config as cfg
}

test_mount_bind_prefix_boundary if {
	cfg := create_cfg({"allowed_bind_prefixes": ["/dev/"]})
	not allow with input as create({"Binds": ["/devious/x:/x"]}) with data.config as cfg
	not allow with input as create({"Binds": ["/dev:/x"]}) with data.config as cfg
}

test_mount_bind_missing_source_denied if {
	cfg := create_cfg({"allowed_bind_prefixes": ["/dev/"]})
	not allow with input as create({"Mounts": [{"Type": "bind", "Target": "/x"}]}) with data.config as cfg
}

test_mount_bind_does_not_bypass_other_denials if {
	cfg := create_cfg({"allowed_bind_prefixes": ["/dev/"]})
	not allow with input as create({"Privileged": true, "Binds": ["/dev/sda:/x"]}) with data.config as cfg
	not allow with input as create({"Privileged": true, "Mounts": [{"Type": "bind", "Source": "/dev/sda", "Target": "/x"}]}) with data.config as cfg
}

test_mount_volume_driver_options_denied if {
	m := {"Type": "volume", "Source": "v", "Target": "/v", "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"type": "none", "o": "bind", "device": "/etc"}}}}
	not allow with input as create({"Mounts": [m]}) with data.config as create_cfg({})
	not allow with input as create({"Mounts": [m]}) with data.config as create_cfg({"allowed_bind_prefixes": ["/etc/"]})
}

test_mount_unknown_type_denied if {
	not allow with input as create({"Mounts": [{"Type": "weird", "Source": "/etc", "Target": "/x"}]}) with data.config as create_cfg({})
	not allow with input as create({"Mounts": [{"Source": "/etc", "Target": "/x"}]}) with data.config as create_cfg({})
}

# ---------------------------------------------------------------------------
# Client network
# ---------------------------------------------------------------------------

test_client_network_default if {
	allow with input as object.union(req("GET", "/_ping"), {"client_ip": "10.1.2.3"}) with data.config as {}
	allow with input as object.union(req("GET", "/_ping"), {"client_ip": "127.0.0.1"}) with data.config as {}
	allow with input as object.union(req("GET", "/_ping"), {"client_ip": "::1"}) with data.config as {}
	not allow with input as object.union(req("GET", "/_ping"), {"client_ip": "8.8.8.8"}) with data.config as {}
	not allow with input as object.union(req("GET", "/_ping"), {"client_ip": ""}) with data.config as {}
}

test_client_network_configured if {
	cfg := {"allowed_client_cidrs": ["8.8.8.0/24"]}
	allow with input as object.union(req("GET", "/_ping"), {"client_ip": "8.8.8.8"}) with data.config as cfg
	not allow with input as object.union(req("GET", "/_ping"), {"client_ip": "10.1.2.3"}) with data.config as cfg
	allow with input as req("GET", "/_ping") with data.config as cfg # unix socket
}

# ---------------------------------------------------------------------------
# Config validation: invalid config reports errors and denies everything
# ---------------------------------------------------------------------------

test_config_valid_has_no_errors if {
	cfg := {"allow": ["exec", "privileged"], "allowed_bind_prefixes": ["/dev/"], "allowed_capabilities": ["NET_ADMIN"], "allowed_client_cidrs": ["10.0.0.0/8"]}
	count(config_errors) == 0 with data.config as cfg
	count(config_errors) == 0 with data.config as {}
}

test_config_unknown_key if {
	count(config_errors) == 1 with data.config as {"allow_bind_prefixes": ["/dev/"]}
}

test_config_unknown_token if {
	count(config_errors) == 1 with data.config as {"allow": ["privilged"]}
}

test_config_wrong_types if {
	count(config_errors) > 0 with data.config as {"allow": "exec"}
	count(config_errors) > 0 with data.config as {"allow": [1]}
	count(config_errors) > 0 with data.config as {"allowed_bind_prefixes": "/dev/"}
	count(config_errors) > 0 with data.config as "nope"
}

test_config_bad_values if {
	count(config_errors) > 0 with data.config as {"allowed_bind_prefixes": ["/dev"]}
	count(config_errors) > 0 with data.config as {"allowed_bind_prefixes": ["dev/"]}
	count(config_errors) > 0 with data.config as {"allowed_bind_prefixes": ["/dev/../"]}
	count(config_errors) > 0 with data.config as {"allowed_client_cidrs": ["not-a-cidr"]}
}

test_config_invalid_denies_everything if {
	not allow with input as req("GET", "/_ping") with data.config as {"allow": ["privilged"]}
	not allow with input as req("GET", "/_ping") with data.config as "nope"
}
