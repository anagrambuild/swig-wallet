# Repository Guidelines

## Project Structure & Module Organization
- `program/`: on-chain Solana program; integration tests under `program/tests` cover instruction flows.
- `interface/`: client bindings that mirror on-chain accounts for off-chain consumers.
- `instructions/` & `state/`: shared instruction builders and account models reused across crates.
- `cli/`: end-user tooling; see `cli/config-example.json` for local config conventions.
- `docs/` & `audits/`: reference architecture notes and external reviews—update when protocol behavior shifts.

## Build, Test, and Development Commands
- `cargo build-sbf` compiles the program to `target/deploy/swig.so` using the Agave toolchain.
- `cargo nextest run --config-file nextest.toml --profile ci --workspace --no-fail-fast` runs the full suite; add feature flags like `--features program_scope_test` for scoped coverage.
- `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features` must pass before review.
- `cargo run -p cli -- --help` checks CLI ergonomics; use `./validator.sh` to spin up a local validator when smoke-testing flows.

## Coding Style & Naming Conventions
- Adhere to Rust 2021 defaults with 4-space indentation and 100-column width per `rustfmt.toml`; run `cargo fmt` pre-commit.
- Organize imports by crate (`group_imports = "StdExternalCrate"`) and avoid glob imports unless justified.
- Name instruction modules with snake_case files and surface builders via `swig-compact-instructions`.
- Respect `.clippy.toml` guidance: control cognitive complexity, keep functions under 200 lines, and avoid `SystemTime::now` on-chain.

## Testing Guidelines
- Store integration tests in `program/tests`; follow the existing `_test.rs` naming for scenario-focused coverage.
- Prefer `cargo nextest` for deterministic results; document feature-flagged suites (`program_scope_test`, `stake_tests`) in PRs.
- Extend shared helpers in `program/tests/common` or `assertions/` to avoid duplication.
- Keep fixtures deterministic and solana-localnet friendly; never depend on external RPC state.

## Commit & Pull Request Guidelines
- Use Conventional Commits (`feat:`, `fix:`, `chore:`) as reflected in history.
- Limit each commit to a cohesive change and rerun format, Clippy, and Nextest before pushing.
- PRs should outline behavior changes, impacted accounts/instructions, linked issues, and manual test notes or screenshots when UI/CLI output shifts.
- Flag breaking protocol changes early and coordinate audit updates when touching `docs/` or `audits/` content.
