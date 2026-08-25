# Release automation

## Goal

Enable tagged releases for this repository and produce reproducible archives for the documented CGO-disabled targets.

## Changes

1. Update GoReleaser metadata to use the current project identity, inject a tag-derived version into the binary, build the supported Linux, Darwin, and Windows targets, and archive checksummed release artifacts.
2. Update GitHub Actions to use maintained checkout/setup/release actions, run the existing verification workflow, and release tags from this repository rather than the upstream fork.
3. Add a `--version` CLI path backed by a linker-overridable version variable, retaining `dev` for ordinary local builds.

## Verification

Run GoReleaser configuration validation if the binary is available, build and test the Go project, confirm the local `--version` path, and inspect the workflow and release configuration before committing and pushing the feature branch.
