# Real-image fixture: Alpine, apk (FR-47..FR-49).
#
# __PIN__ is replaced by the test harness with the current apk version of
# curl, resolved fresh at build time for the same reason as the Debian
# fixture: Alpine's main repo only carries the latest build per release
# branch.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache curl=__PIN__
CMD ["curl", "--version"]
