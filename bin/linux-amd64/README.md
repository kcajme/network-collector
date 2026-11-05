# Linux x86-64 binary

`network-collector` is built from this repository with Go 1.27.3 for Linux
AMD64 (x86-64), with CGO disabled and the baseline AMD64 instruction set.
It is statically linked and does not require Go to be installed on the target.

From the repository root:

```sh
./bin/linux-amd64/network-collector --version
./bin/linux-amd64/network-collector --config your-playbook.yaml --lint
```

Keep the configuration's referenced inventory, parser files and templates
available on the target system. Actual device connections need the appropriate
credentials and network access.

Verify the binary:

```sh
cd bin/linux-amd64
sha256sum -c SHA256SUMS
```

Rebuild from the repository root with Go 1.27.3:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOFLAGS=-mod=readonly \
  go build -trimpath -ldflags="-s -w -X main.version=$(cat VERSION)-progress" \
  -o bin/linux-amd64/network-collector ./cmd/network-collector
(cd bin/linux-amd64 && sha256sum network-collector > SHA256SUMS)
```

This build reports `2.0.2-progress` and supports the bounded
`register_integer` capture documented in the repository README.

Terminal runs prompt automatically when environment credentials are incomplete.
Configured providers and complete environment credentials remain supported.

This build adds the live host progress table and optional step `category` labels.
