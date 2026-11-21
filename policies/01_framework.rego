package policies

# ============================================================================
# Decision framework.
#
# A request is allowed when BOTH hold:
#   1. request_permitted — the operation is enabled. By default only
#      read-only requests are; more are enabled via `policy.allow` in the
#      config (03_operations.rego).
#   2. denial is empty — no hardening rule objects. Denials can not be
#      overridden by any permissive rule; they are relaxed only through
#      config (the rules themselves read it).
#
# Policy files extend the system by adding to `denial` or by adding bodies to
# `request_permitted`. Nothing else may define `allow`.
# ============================================================================

default allow := false

allow if {
	request_permitted
	count(denial) == 0
}

# Invalid configuration denies everything.
denial contains sprintf("invalid policy config: %s", [e]) if some e in config_errors

default request_permitted := false

# Human-readable explanation of a denial.
default reason := ""

reasons contains msg if some msg in denial

reasons contains not_permitted_message if not request_permitted

reason := concat("; ", reasons) if not allow
