# Lista as receitas disponíveis ao rodar apenas `just`.
default:
  @just --list

# Formata o código Rust.
fmt:
  cargo fmt --all

# Verifica a formatação sem alterar arquivos.
fmt-check:
  cargo fmt --all -- --check

# Executa todos os testes, descobrindo o Git local quando não informado.
test:
  PERSONA_TEST_GIT="${PERSONA_TEST_GIT:-$(command -v git)}" cargo test

# Executa apenas os testes de resolução de escopos.
test-scope:
  cargo test --test scope

# Executa o Clippy e trata avisos como erros.
clippy:
  cargo clippy --all-targets -- -D warnings

# Validação completa.
check: fmt-check test clippy

# Compila a versão de release.
build:
  cargo build --release
