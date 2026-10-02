package policies

# ============================================================================
# Block access to secrets and configs.
# ============================================================================

denial contains "secrets and configs are not accessible" if {
	startswith(input.path, "/secrets")
}

denial contains "secrets and configs are not accessible" if {
	startswith(input.path, "/configs")
}
