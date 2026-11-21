package policies

# ============================================================================
# Restrict which clients may use the proxy.
# Allowed networks are policy.allowed_client_cidrs (default: loopback and
# RFC1918). Unix-socket clients (client_ip "@") are always allowed.
# ============================================================================

client_allowed if input.client_ip == "@"

client_allowed if {
	some cidr in cfg.allowed_client_cidrs
	net.cidr_contains(cidr, input.client_ip)
}

denial contains "client address is not in policy.allowed_client_cidrs" if not client_allowed
