#!/usr/bin/env python3
"""NFR-18 for the container image: the layer imgowner adds on top of its pinned
Trivy base may contain the imgowner binary and nothing else.

The image is `FROM aquasec/trivy@sha256:...` plus a single `COPY imgowner`, so
its last layer is the only one that is ours. `docker save` writes every layer
as a tar; this lists the last one and fails on anything outside the allowlist.
No third-party packages: standard library only.

Usage: check-image-contents.py <image-ref>
"""
import json
import subprocess
import sys
import tarfile
import tempfile
import os

ALLOWED = {
    "usr",
    "usr/local",
    "usr/local/bin",
    "usr/local/bin/imgowner",
}


def last_layer_names(archive: str):
    """Returns (layer count, normalised member names of the last layer)."""
    with tarfile.open(archive) as image:
        manifest = json.load(image.extractfile("manifest.json"))
        layers = manifest[0]["Layers"]
        if not layers:
            return 0, []
        with tarfile.open(fileobj=image.extractfile(layers[-1])) as layer:
            return len(layers), [m.name.strip("./").rstrip("/") for m in layer.getmembers()]


def verdict(ref: str, count: int, names) -> int:
    if count == 0:
        print(f"::error::{ref} has no layers")
        return 1
    print(f"checking {ref}: {count} layers, inspecting the last")
    bad = [n for n in names if n and n not in ALLOWED]
    for n in bad:
        print(f"::error::{ref} adds a disallowed file in its last layer: {n}")
    if "usr/local/bin/imgowner" not in names:
        print(f"::error::{ref}'s last layer does not contain usr/local/bin/imgowner")
        bad.append("missing binary")
    if bad:
        print("::error::container image content check failed; release stays draft")
        return 1
    print("the image's own layer contains only the imgowner binary")
    return 0


def main() -> int:
    ref = sys.argv[1]
    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "image.tar")
        subprocess.run(["docker", "save", "-o", archive, ref], check=True)
        count, names = last_layer_names(archive)
    return verdict(ref, count, names)


if __name__ == "__main__":
    sys.exit(main())
