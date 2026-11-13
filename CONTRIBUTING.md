# Contributing to Persona

Thanks for your interest in contributing. Persona is a release candidate and its maintainer has final decision-making authority. Issues and pull requests are welcome; review and support are best-effort with no response-time guarantee. A proposed change is not accepted until the maintainer approves and merges it.

## Before opening a large change

For behavior or security-boundary changes, open an issue first to discuss scope and tests. Keep pull requests focused. Documentation fixes and tests are welcome. Do not include real identities, local absolute paths, tokens, private keys, credential-store data, or provider output in issues, fixtures, or commits. Use synthetic identities and `.invalid` domains.

## Development setup

Use Rust 1.85 or newer, Git, GnuPG, OpenSSH and GitHub CLI; test suites also need Zsh, OpenSSL and local SSH server tooling. The project has no requirement for a live GitHub account: provider tests use synthetic identities and local fixtures. Never run a contribution test against a real account or repository.

Useful commands:

```sh
just fmt
just fmt-check
just test
just clippy
just msrv-check
just check
just docs-check
cargo build --locked --release
```

Some transport tests need local loopback TLS/SSH fixtures and may be skipped by the Nix sandbox with an explicit recorded reason. Do not turn failures into skips or retries to make CI green. CI validates macOS arm64, Linux arm64 and Linux x86_64.

## Pull request expectations

- Explain the problem, scope and user-visible behavior.
- Add or update tests for behavior; keep network/provider testing synthetic and local.
- Update the canonical guide and CLI help when the command contract changes.
- State exact validation commands and results, including skips and environment limitations.
- Call out security-boundary changes and residual risks explicitly.

The project uses the dual `MIT OR Apache-2.0` license. By intentionally submitting a contribution for inclusion, you agree that it is offered under those same terms, consistent with Apache-2.0 section 5. No CLA or DCO is required. Do not submit material you cannot license on these terms.
