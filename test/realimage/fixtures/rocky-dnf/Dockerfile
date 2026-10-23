# Real-image fixture: Rocky Linux, dnf (FR-47..FR-49).
#
# wget, not curl: Rocky's minimal image ships curl-minimal, which conflicts
# with the "curl" package on the file it installs at /usr/bin/curl. wget is
# absent by default and installs cleanly.
#
# __PIN__ is the version-release portion of an rpm NVR (e.g. "1.21.1-11.el9_8"),
# resolved fresh at build time for the same reason as the other fixtures:
# BaseOS/AppStream only carry the latest build per package.
FROM rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6
RUN dnf install -y wget-__PIN__ && dnf clean all
CMD ["wget", "--version"]
