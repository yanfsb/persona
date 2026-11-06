# Lista as receitas disponíveis ao rodar apenas `just`.
default:
  @just --list

# Formata o código Rust.
fmt:
  cargo fmt --all

# Verifica a formatação sem alterar arquivos.
fmt-check:
  cargo fmt --all -- --check

# Executa toda a suíte com ferramentas nativas localizadas uma vez.
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
  PERSONA_TEST_COREUTILS="$(dirname "$(command -v cat)")" \
  cargo test --locked --all-targets -- --nocapture --test-threads=1

# Executa apenas os testes de resolução de escopos.
test-scope:
  cargo test --locked --test scope

# Executa o Clippy e trata avisos como erros.
clippy:
  cargo clippy --locked --all-targets -- -D warnings

# Verifica que todas as targets continuam compatíveis com a MSRV declarada.
msrv-check:
  cargo +1.85 check --locked --all-targets

# Validação completa.
check: fmt-check test clippy msrv-check

# Compila a versão de release.
build:
  cargo build --locked --release
