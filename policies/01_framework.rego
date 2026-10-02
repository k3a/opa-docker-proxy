package policies

# ============================================================================
# Deny framework — provides the denial accumulator and the master allow rule.
#
# Other policy files contribute entries to the "denial" set.  When denial is
# non-empty the request is rejected, regardless of any permissive allow rules
# defined in the basic policies.
# ============================================================================

# denial is a set of human-readable messages.  Each security policy file adds
# one or more entries when a rule is violated.  When no deny rule matches,
# the set remains empty and requests are allowed (subject to the allow rules
# in other policy files).

default allow := false

# A request is allowed only when nothing denies it.
allow if {
    count(denial) == 0
}

# A reason text describing the denial.
default reason := ""

# Join all denial messages into a single string, or use the default if allowed.
reason := concat("; ", denial) if {
    not allow
}
