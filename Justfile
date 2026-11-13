# List available recipes when running `just` without arguments.
default:
  @just --list

# Format the Rust source code.
fmt:
  cargo fmt --all

# Check formatting without changing files.
fmt-check:
  cargo fmt --all -- --check

# Run the full suite with native test tools resolved once.
test:
  PERSONA_TEST_GIT="$(command -v git)" \
  PERSONA_TEST_GPG="$(command -v gpg)" \
  PERSONA_TEST_NATIVE_GH="$(command -v gh)" \
  PERSONA_TEST_ZSH="$(command -v zsh)" \
  PERSONA_TEST_SSH="$(command -v ssh)" \
  PERSONA_TEST_SSH_KEYGEN="$(command -v ssh-keygen)" \
  PERSONA_TEST_SSH_AGENT="$(command -v ssh-agent)" \
  PERSONA_TEST_SSH_ADD="$(command -v ssh-add)" \
  PERSONA_TEST_SSHD="$(command -v sshd)" \
  PERSONA_TEST_OPENSSL="$(command -v openssl)" \
  PERSONA_TEST_CAT="$(command -v cat)" \
  PERSONA_TEST_CP="$(command -v cp)" \
  PERSONA_TEST_COREUTILS="$(dirname "$(command -v cat)")" \
  cargo test --locked --all-targets --features test-support -- --nocapture --test-threads=1

# Run only scope-resolution tests.
test-scope:
  cargo test --locked --test scope

# Run Clippy and treat warnings as errors.
clippy:
  cargo clippy --locked --all-targets --features test-support -- -D warnings

# Check all targets against the declared MSRV.
msrv-check:
  cargo +1.85 check --locked --all-targets --features test-support

# Check local Markdown links and documentation navigation.
docs-check:
  cargo test --locked --test documentation

# Run the complete validation suite.
check: fmt-check test clippy msrv-check docs-check

# Build the release binary.
build:
  cargo build --locked --release
