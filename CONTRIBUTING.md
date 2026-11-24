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

After any change to `go.mod`/`go.sum`, the Nix flake's `vendorHash` is stale and `nix build` fails with a hash mismatch. The `Nix` CI workflow builds the flake on every PR to catch this, and on Renovate PRs the `Nix vendorHash` workflow recomputes the hash and pushes the fix for you.

For your own dependency changes, recompute it by hand:

```sh
nix build .#default   # fails with "got: sha256-…"; paste that into vendorHash in flake.nix
nix build .#default   # confirm it succeeds
```

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

The flake builds the tree it lives in, so a release tag is only a correct, pinnable flake if `flake.nix` already has the new version when you tag. The release workflow fails before publishing anything if they don't match.

```sh
sed -i '' -E 's/version = "[^"]+";/version = "0.13.0";/' flake.nix
git commit -am "quien: 0.12.0 -> 0.13.0"
git push origin main
git tag v0.13.0
git push origin v0.13.0
```

Make sure the `Nix` workflow is green on `main` before tagging.
