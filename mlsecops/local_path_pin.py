"""Shared identity of the qualified linux/amd64 local-path provisioner."""

REPOSITORY = "ghcr.io/abrakadabra124/trusted-mlsecops-platform/local-path"
PUBLISHED_CONFIG = "sha256:6a8aed8ef83dc8563559bd755adfc2f9e5f64d5ba3606aa71ad8841a1826434a"
# GHCR linux/amd64 manifest readback in publication run 45049960229.
PUBLISHED_REFERENCE: str | None = (
    REPOSITORY + "@sha256:6379f416ad3c2369fa5c25e654dc4408ac441e06ca0522e5728567ef0275a863"
)
