# ========================================================================
# Makefile NetSentinel (Monorepo Pure Rust Workspace)
#
# Cibles UTILISATEUR principales :
#   make test          # cargo test --workspace (exclut eBPF)
#   make check         # cargo check --workspace (exclut eBPF)
#   make clippy        # cargo clippy --workspace (exclut eBPF)
#   make build-deb     # cargo build workspace + dpkg staging
#   make clean         # cargo clean
# ========================================================================

SHELL := /bin/bash
CARGO := cargo
RUST_DIR := netsentinel-workspace/netsentinel

.PHONY: all check test clippy build-deb clean help

all: check test clippy

check:
	@echo "▶ Rust workspace check ..."
	@cd $(RUST_DIR) && $(CARGO) check --workspace --exclude netsentinel-capture-ebpf

test:
	@echo "▶ Rust workspace unit tests ..."
	@cd $(RUST_DIR) && $(CARGO) test --workspace --exclude netsentinel-capture-ebpf

clippy:
	@echo "▶ Rust workspace clippy linter ..."
	@cd $(RUST_DIR) && $(CARGO) clippy --workspace --exclude netsentinel-capture-ebpf

build-deb:
	@echo "▶ Build .deb via workspace Cargo + staging"
	@cd $(RUST_DIR) && $(CARGO) build --workspace --profile release --bins --exclude netsentinel-capture-ebpf
	@cd $(RUST_DIR) && ./packaging/build_staging.sh 2>/dev/null || \
	  echo "⚠ build_staging.sh absent ; utilisez plutôt .github/workflows/ci.yml job 6 (staging complet avec dpkg-shlibdeps)."

clean:
	@echo "▶ Nettoyage cibles cargo"
	@cd $(RUST_DIR) && $(CARGO) clean 2>/dev/null || true

help:
	@echo "Cibles NetSentinel (Pure Rust Monorepo) :"
	@echo "  check      — cargo check --workspace"
	@echo "  test       — cargo test --workspace"
	@echo "  clippy     — cargo clippy --workspace"
	@echo "  build-deb  — cargo build workspace (staging Debian)"
	@echo "  clean      — cache cibles cargo"
