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
  go build -trimpath -ldflags="-s -w -X main.version=$(cat VERSION)-column-labels" \
  -o bin/linux-amd64/network-collector ./cmd/network-collector
(cd bin/linux-amd64 && sha256sum network-collector > SHA256SUMS)
```

This build reports `2.0.2-column-labels` and supports the bounded
`register_integer` capture documented in the repository README.

Terminal runs prompt automatically when environment credentials are incomplete.
Configured providers and complete environment credentials remain supported.

This build adds the live host progress table and optional step `category` labels.

Use `q` then Enter and confirm with `y` then Enter to quit the live menu.
Ctrl+C is ignored while the terminal menu is available.

The menu stays open after jobs finish. Use `r <ID>` to retry an eligible failed
host from its in-memory checkpoint, or `q` and confirm to exit.

The progress view adapts to terminal size. Use `n`/`p` to page hosts or
`g <ID>` to jump to a host; press Enter after each command.

The editable `Command>` line preserves partial input across redraws; larger
terminals use a framed ASCII progress view and shortcut legend.

Host totals and menu stay anchored above the bottom command line, independently
of the number of visible hosts.

Nano-style controls: Ctrl+V next page, Ctrl+Y previous page, Ctrl+G help,
Ctrl+X exit confirmation, Ctrl+R retry host, and Ctrl+W find host.

Inventory uses `hosts:` entries with only `name` and `ip`. A shared workflow
sets `type` once and omits host/group selectors to target every inventory host.
