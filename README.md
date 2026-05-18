<p align="center">
  <img src="docs/banner.svg" alt="Open Ports — Dispersal Wolves" width="100%">
</p>

# Open Ports

**See what is listening and what changed.**

Inventories local TCP and UDP listeners, records a baseline, and compares later scans. It does not probe remote systems.

## Start

```console
cargo run -- scan --format table
```

Run the command with `--help` for every option. The tool works locally, collects no telemetry, and supports machine-readable output where applicable.

## Principles

- **Local first.** Host data stays on the host unless you explicitly configure a webhook.
- **Safe by default.** Inspection is read-only and mutation requires a deliberate command.
- **Small contract.** The tool solves one defensive job and reports its limits plainly.
- **Scriptable.** Stable exit codes and structured output make automation practical.

## Platform

The initial release targets Linux. Portable behavior is also tested on Windows where the underlying operating-system facilities allow it. See [the threat model](docs/threat-model.md) for trust boundaries and non-goals.

## Development

This repository uses **Rust** without third-party crates.

```console
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

## License

[MIT](LICENSE) © Dispersal Wolves.
