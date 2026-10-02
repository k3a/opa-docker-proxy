package policies

# ============================================================================
# Tests for 50_allow_safe_host_mounts.rego
# ============================================================================

import future.keywords

# ---------------------------------------------------------------------------
# Helper: build a fully qualified mock input for /containers/create with
# all fields needed to avoid denials from other policy files.
# ---------------------------------------------------------------------------
mock_input(mounts, binds) := {
	"path": "/containers/create",
	"method": "POST",
	"client_ip": "10.0.0.1", # internal IP — satisfies 06_internal_network.rego
	"body": {
		"HostConfig": {
			"Mounts": mounts,
			"Binds": binds,
		},
	},
}

# ---------------------------------------------------------------------------
# all_bind_sources tests — note: sources are collected raw, ".." is NOT
# filtered; that is handled separately by any_dotdot_in_bind_sources.
# ---------------------------------------------------------------------------

test_bind_source_from_mounts if {
	sources := all_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/dev/sda"}],
		[],
	)
	sources == {"/dev/sda"}
}

test_bind_source_from_binds if {
	sources := all_bind_sources with input as mock_input(
		[],
		["/dev/sda:/mnt:ro"],
	)
	sources == {"/dev/sda"}
}

test_bind_sources_from_both if {
	sources := all_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/dev/sda"}],
		["/temp/agent/data:/data:ro"],
	)
	sources == {"/dev/sda", "/temp/agent/data"}
}

# all_bind_sources now includes sources with ".." — they are not filtered
# out here so that any_dotdot_in_bind_sources can detect them.
test_bind_source_includes_dotdot_in_mounts if {
	sources := all_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/dev/../etc"}],
		[],
	)
	sources == {"/dev/../etc"}
}

test_bind_source_includes_dotdot_in_binds if {
	sources := all_bind_sources with input as mock_input(
		[],
		["/dev/../etc:/etc:ro"],
	)
	sources == {"/dev/../etc"}
}

test_bind_source_skips_non_bind_mounts if {
	sources := all_bind_sources with input as mock_input(
		[
			{"Type": "volume", "Source": "myvol"},
			{"Type": "bind", "Source": "/dev/sda"},
		],
		[],
	)
	sources == {"/dev/sda"}
}

test_bind_source_handles_binds_without_options if {
	sources := all_bind_sources with input as mock_input(
		[],
		["/temp/agent/data:/app/data"],
	)
	sources == {"/temp/agent/data"}
}

# ---------------------------------------------------------------------------
# bind_source_from_entry tests
# ---------------------------------------------------------------------------

test_bind_source_entry_src_dst if {
	bind_source_from_entry("/host:/container") == "/host"
}

test_bind_source_entry_src_dst_opts if {
	bind_source_from_entry("/host:/container:ro") == "/host"
}

test_bind_source_entry_src_dst_multi_opts if {
	bind_source_from_entry("/host:/container:ro,Z") == "/host"
}

# ---------------------------------------------------------------------------
# any_dotdot_in_bind_sources tests
# ---------------------------------------------------------------------------

test_dotdot_detected_in_mounts_middle if {
	any_dotdot_in_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/dev/../etc"}],
		[],
	)
}

test_dotdot_detected_in_binds_middle if {
	any_dotdot_in_bind_sources with input as mock_input(
		[],
		["/dev/../etc:/etc:ro"],
	)
}

test_dotdot_detected_at_start if {
	any_dotdot_in_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "../etc"}],
		[],
	)
}

test_dotdot_detected_at_end if {
	any_dotdot_in_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/dev/.."}],
		[],
	)
}

test_dotdot_detected_exact if {
	any_dotdot_in_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": ".."}],
		[],
	)
}

# Paths that contain ".." as a substring but NOT as a path component should
# NOT trigger the rule (e.g., "/tmp/..foo" contains ".." but is not a parent
# directory reference).
test_dotdot_not_false_positive_substring if {
	not any_dotdot_in_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/tmp/..foo"}],
		[],
	)
}

test_dotdot_not_false_positive_dots_alone if {
	not any_dotdot_in_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/tmp/...bar"}],
		[],
	)
}

test_dotdot_not_detected_on_clean_path if {
	not any_dotdot_in_bind_sources with input as mock_input(
		[{"Type": "bind", "Source": "/dev/sda"}],
		[],
	)
}

# ---------------------------------------------------------------------------
# any_disallowed_bind_source tests
# ---------------------------------------------------------------------------

test_no_disallowed_when_all_dev if {
	not any_disallowed_bind_source({"/dev/sda", "/dev/sdb"})
}

test_no_disallowed_when_all_temp_agent if {
	not any_disallowed_bind_source({"/temp/agent/data", "/temp/agent/logs"})
}

test_no_disallowed_when_mixed_allowed if {
	not any_disallowed_bind_source({"/dev/sda", "/temp/agent/data"})
}

test_disallowed_when_etc_shared if {
	any_disallowed_bind_source({"/dev/sda", "/etc/shared"})
}

test_disallowed_when_opt if {
	any_disallowed_bind_source({"/opt/app"})
}

# ---------------------------------------------------------------------------
# non_bind_mount_denial_exists tests
# ---------------------------------------------------------------------------

test_non_bind_denial_false_with_bind_only if {
	not non_bind_mount_denial_exists with denial as {"bind mounts are not allowed"}
}

test_non_bind_denial_true_with_privileged if {
	non_bind_mount_denial_exists with denial as {
		"bind mounts are not allowed",
		"privileged containers are not allowed",
	}
}

test_non_bind_denial_true_with_other if {
	non_bind_mount_denial_exists with denial as {"some other denial"}
}

# ---------------------------------------------------------------------------
# allow integration tests (with denial overridden to simulate only overridable
# denials being present).
# ---------------------------------------------------------------------------

test_allow_with_mounts if {
	allow with input as mock_input(
		[{"Type": "bind", "Source": "/dev/sda"}],
		[],
	) with denial as {"bind mounts are not allowed"}
}

test_allow_with_binds if {
	allow with input as mock_input(
		[],
		["/dev/sda:/dev/sda:ro"],
	) with denial as {"bind mounts are not allowed"}
}

test_allow_with_both if {
	allow with input as mock_input(
		[{"Type": "bind", "Source": "/dev/sda"}],
		["/temp/agent/data:/data:ro"],
	) with denial as {"bind mounts are not allowed"}
}

test_deny_when_dotdot_in_mounts if {
	not allow with input as mock_input(
		[{"Type": "bind", "Source": "/dev/../etc"}],
		[],
	) with denial as {"bind mounts are not allowed"}
}

test_deny_when_dotdot_in_binds if {
	not allow with input as mock_input(
		[],
		["/dev/../etc:/etc:ro"],
	) with denial as {"bind mounts are not allowed"}
}

test_deny_when_disallowed_path_in_mounts if {
	not allow with input as mock_input(
		[{"Type": "bind", "Source": "/etc/shared"}],
		[],
	) with denial as {"bind mounts are not allowed"}
}

test_deny_when_disallowed_path_in_binds if {
	not allow with input as mock_input(
		[],
		["/etc/shared:/mnt:ro"],
	) with denial as {"bind mounts are not allowed"}
}

test_deny_when_no_bind_mounts if {
	not allow with input as mock_input(
		[{"Type": "volume", "Source": "myvol"}],
		[],
	) with denial as {"bind mounts are not allowed"}
}

test_deny_when_binds_and_mounts_empty if {
	not allow with input as {"path": "/containers/create", "body": {"HostConfig": {"Mounts": [], "Binds": []}}}
		with denial as {"bind mounts are not allowed"}
}

test_deny_when_no_path_match if {
	not allow with input as {"path": "/containers/start", "method": "POST", "client_ip": "10.0.0.1", "body": {"HostConfig": {"Mounts": [{"Type": "bind", "Source": "/dev/sda"}], "Binds": []}}}
		with denial as {"bind mounts are not allowed"}
}

# ---------------------------------------------------------------------------
# End-to-end tests: exercise the full policy stack (no denial overrides).
#
# The permissive allow rule in 50_allow_safe_host_mounts.rego is designed to
# override BOTH the "bind mounts are not allowed" denial (from 02) and the
# "creation of containers is denied" denial (from 07) when the bind sources
# are all safe.
# ---------------------------------------------------------------------------

test_e2e_allow_safe_mounts if {
	allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Mounts": [{"Type": "bind", "Source": "/dev/sda"}],
			},
		},
	}
}

test_e2e_allow_safe_binds if {
	allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Binds": ["/dev/sda:/dev/sda:ro"],
			},
		},
	}
}

test_e2e_allow_safe_both if {
	allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Mounts": [{"Type": "bind", "Source": "/dev/sda"}],
				"Binds": ["/temp/agent/data:/data:ro"],
			},
		},
	}
}

test_e2e_deny_unsafe_mounts if {
	not allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Mounts": [{"Type": "bind", "Source": "/etc/shared"}],
			},
		},
	}
}

test_e2e_deny_unsafe_binds if {
	not allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Binds": ["/etc/shared:/mnt:ro"],
			},
		},
	}
}

test_e2e_deny_mounts_with_dotdot if {
	not allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Mounts": [{"Type": "bind", "Source": "/dev/../etc"}],
			},
		},
	}
}

test_e2e_deny_binds_with_dotdot if {
	not allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Binds": ["/dev/../etc:/etc:ro"],
			},
		},
	}
}

# Mix of valid source and dotdot source must still be denied.
test_e2e_deny_mixed_valid_and_dotdot if {
	not allow with input as {
		"path": "/containers/create",
		"method": "POST",
		"client_ip": "10.0.0.1",
		"body": {
			"HostConfig": {
				"Mounts": [
					{"Type": "bind", "Source": "/dev/sda"},
					{"Type": "bind", "Source": "/dev/../etc"},
				],
			},
		},
	}
}
