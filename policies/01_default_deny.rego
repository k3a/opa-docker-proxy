package policies

# ---------------------------------------------------------------------------
# Default deny — every request must match at least one allow rule.
# ---------------------------------------------------------------------------
default allow := false

# Optionally provide a reason when denying.
reason := "denied by default" {
    not allow
}