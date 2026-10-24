# Release container image (FR-41, NFR-07). Built once per release by
# goreleaser from the already-built linux binary; never built as part of the
# staging/main CI pipeline, which only needs the binary itself.
#
# FROM a pinned Trivy image rather than installing it separately: `docker run
# imgowner ci ...` then needs nothing else, and the Trivy version is locked to
# an exact digest rather than whatever "latest" resolves to at build time.
FROM aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222

# goreleaser's docker build context for this Dockerfile is the directory
# holding the single binary built for the image's own platform (see
# .goreleaser.yml dockers.extra_files); COPY takes it from there, not from a
# `go build` run inside this image, so the shipped binary is byte-for-byte
# the one SBOM'd and signed alongside the archives for this release.
COPY imgowner /usr/local/bin/imgowner

ENTRYPOINT ["/usr/local/bin/imgowner"]
