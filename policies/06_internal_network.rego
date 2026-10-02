package policies

# ============================================================================
# Restrict access from internal/private networks or a socket only.
# ============================================================================

internal_cidrs := {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
}

is_internal_ip if {
    some cidr in internal_cidrs
    net.cidr_contains(cidr, input.client_ip)
}

denial contains "access restricted to internal network" if {
    not is_internal_ip
    not input.client_ip == "@" # socket file
}
