# Contributing

## Development

quien is a standard Go module:

```sh
go build ./...
go test ./...
gofmt -l .                # must report nothing
golangci-lint run ./...   # CI uses the latest release
```

CI also enforces the `modernize` analyzer:

```sh
go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest ./...
```

## Bumping dependencies

After any change to `go.mod`/`go.sum`, the Nix flake's `vendorHash` is stale. The `Nix` CI workflow builds the flake on every PR to catch this, and on Renovate PRs the `Nix vendorHash` workflow recomputes the hash and pushes the fix for you.

For your own dependency changes, recompute it by hand:

```sh
# set vendorHash in flake.nix to a fake value, then build to learn the real one:
nix build .#default   # prints "got: sha256-…"; paste that into flake.nix
nix build .#default   # confirm it succeeds
```

Use a fake value rather than building with the old hash: if the old Go modules are already in your Nix store, Nix reuses them and you get a confusing vendoring error instead of the new hash.

## Bumping the Go toolchain

The Go version lives in two coupled places that **must move together**:

1. The `go` directive in `go.mod`.
2. The flake's `nixpkgs` input in `flake.nix`, which supplies the Go compiler used by `nix build`. It is pinned to a stable channel (e.g. `nixos-26.05`).

The release process doesn't touch the `nixpkgs` input, so the toolchain only moves when you bump it by hand:

1. Check which channel actually ships the Go version you want — a stable release branch sometimes carries a newer patch than `nixpkgs-unstable`:
   ```sh
   nix eval --raw github:NixOS/nixpkgs/nixos-26.05#go.version
   ```
2. Update the directive (`go mod edit -go=1.26.4`) and, if needed, point `inputs.nixpkgs.url` at the channel that has it.
3. Re-lock and recompute the vendor hash (see *Bumping dependencies* above):
   ```sh
   nix flake update
   nix build .#default
   ```
4. Verify: `go build ./... && go test ./... && nix build .#default`.

If `go.mod` requires a newer Go than the pinned `nixpkgs` provides, `nix build` fails because the sandbox can't download a toolchain — that's the symptom of the two having drifted apart.

## Releasing

Release from the **Release** workflow's **Run workflow** button, or:

```sh
gh workflow run release.yml -f version=0.13.0
```

The workflow bumps `version` in `flake.nix` on `main`, checks that the flake builds, tags that commit, and publishes the release. Because the flake builds the tree it lives in, this keeps every release tag a correct, pinnable flake. The version must be newer than the latest stable release, since tags can never be moved once pushed (`go install` pins them).

Prereleases (e.g. `0.13.0-rc.1`) tag `main` without touching the flake, publish as GitHub prereleases, and skip the apt and AUR steps.

If a release fails after the tag is pushed, use **Re-run failed jobs**, not **Re-run all jobs**: the tag job would fail because the tag already exists.

Pushing a tag by hand still works, but the release fails before publishing anything if `flake.nix` doesn't already have the matching version.
