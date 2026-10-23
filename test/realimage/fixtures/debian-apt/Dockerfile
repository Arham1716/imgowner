# Real-image fixture: Debian multi-stage, apt (FR-47..FR-49).
#
# __PIN__ is replaced by the test harness with the apt candidate version of
# curl at build time (see resolvePin in realimage_test.go). Debian's archive
# keeps only the latest build of each package per release, so a version
# literal written here would eventually stop being installable; resolving it
# fresh on every run means the fixture never goes stale.
#
# Both stages use the same digest-pinned base so the final image's base layer
# boundary is unambiguous: the base is exactly what this file names, not
# whatever "debian:12-slim" happens to point to today.
FROM debian:12-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS build
WORKDIR /app
RUN printf '#!/bin/sh\necho hello from imgowner real-image fixture\n' > run.sh && chmod +x run.sh

FROM debian:12-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update && apt-get install -y --no-install-recommends curl=__PIN__ && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/run.sh /app/run.sh
CMD ["/app/run.sh"]
