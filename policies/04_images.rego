package policies

# ============================================================================
# Image allowlist (policy.allowed_images).
#
# Empty (default) = any image. When set, container creation and pulls are
# limited to matching image references. A pattern is a glob ("*" matches any
# characters, including "/" and ":"). It is matched against the reference as
# the client wrote it, and against the repository part (tag and digest
# removed), so "alpine" allows every tag of alpine while "alpine:3.19" only
# that tag. List both "alpine" and "docker.io/library/alpine" if clients use
# either form.
#
# Without isolation, local images referenced by ID (sha256:...) are denied
# unless a pattern matches them. Image builds (FROM lines) are not covered.
#
# With isolation the proxy enforces this itself (it knows which images are the
# client's own, which are always usable), and also uses image_visible() below
# to hide pulled (unlabelled) images that no pattern matches from lists and
# inspect calls — see package isolation.
# ============================================================================

images_restricted if count(cfg.allowed_images) > 0

# Repository part of a reference: strip "@digest" and a ":tag" on the last
# path segment (a registry port like localhost:5000/ is not a tag).
image_repo(ref) := repo if {
	no_digest := split(ref, "@")[0]
	segments := split(no_digest, "/")
	parts := split(segments[count(segments) - 1], ":")
	count(parts) == 2
	repo := trim_suffix(no_digest, concat("", [":", parts[1]]))
} else := split(ref, "@")[0]

image_allowed(ref) if {
	some candidate in {ref, image_repo(ref)}
	some pattern in cfg.allowed_images
	glob.match(pattern, [], candidate)
}

# The image a pull asks for: fromImage, plus tag if given separately.
pull_ref := ref if {
	from := input.query.fromImage[0]
	tag := input.query.tag[0]
	not contains(regex.replace(from, `^.*/`, ""), ":")
	not contains(from, "@")
	ref := concat(":", [from, tag])
} else := input.query.fromImage[0]

# For Go: is an image with these references (name used, repo tags, digests)
# acceptable under allowed_images? Any one matching reference is enough.
image_visible(refs) if not images_restricted

image_visible(refs) if {
	some ref in refs
	image_allowed(ref)
}

# With isolation on, the proxy checks image use itself.
denial contains sprintf("image %q is not in policy.allowed_images", [img]) if {
	is_container_create
	isolation_mode == "off"
	images_restricted
	img := input.body.Image
	is_string(img)
	not image_allowed(img)
}

denial contains sprintf("pulling image %q is not allowed (policy.allowed_images)", [pull_ref]) if {
	input.method == "POST"
	input.path == "/images/create"
	images_restricted
	not image_allowed(pull_ref)
}

# Importing from a URL or stream (fromSrc) bypasses the allowlist.
denial contains "importing images is not allowed when policy.allowed_images is set" if {
	input.method == "POST"
	input.path == "/images/create"
	images_restricted
	count(input.query.fromSrc) > 0
}
