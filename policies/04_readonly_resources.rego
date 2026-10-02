package policies

# ============================================================================
# Read-only resources — mutations are forbidden.
# ============================================================================

# ---------------------------------------------------------------------------
# readonly-volumes
# Only GET is permitted on /volumes.
# ---------------------------------------------------------------------------
denial contains "volume mutations are forbidden" if {
	startswith(input.path, "/volumes")
	input.method != "GET"
}

# ---------------------------------------------------------------------------
# readonly-networks
# Only GET is permitted on /networks.
# ---------------------------------------------------------------------------
denial contains "network mutations are forbidden" if {
	startswith(input.path, "/networks")
	input.method != "GET"
}

# ---------------------------------------------------------------------------
# readonly-images
# Only GET is permitted on /images.
# ---------------------------------------------------------------------------
denial contains "image mutations are forbidden" if {
	startswith(input.path, "/images")
	input.method != "GET"
}
