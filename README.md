# Swig

Smart wallet infrastructure for programmable money movement.

Swig gives fintechs, banks, and agents self-custodial wallets with granular onchain policies. Users hold their keys. Policies are enforced by the program itself, so there is no server in the path deciding what a wallet can do.

This repository contains the Swig protocol: the onchain wallet program for Solana, along with the Rust SDK and CLI that sit on top of it.

- Website: [onswig.com](https://onswig.com)
- Docs: [build.onswig.com](https://build.onswig.com)
- Dashboard: [dashboard.onswig.com](https://dashboard.onswig.com)
- Program ID: `swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB`
  - [Mainnet](https://explorer.solana.com/address/swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB)
  - [Devnet](https://explorer.solana.com/address/swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB?cluster=devnet)

## Why Swig

Most wallets are a single key. Whoever holds it can do anything, and the only way to share access is to share the key. That works for one person moving their own funds. It does not work for a payroll app, a subscription service, a trading desk, or an AI agent that needs to spend on someone's behalf.

Swig separates who can sign from what they are allowed to do. A wallet can have many signers, and each one gets its own set of permissions: which programs it can call, which tokens it can move, how much it can spend, and for how long. Those rules live onchain and are checked on every transaction. If the backend goes down or gets compromised, the rules still hold.

## How it works

A Swig wallet is made up of a config account that stores roles, and a wallet address that signs for normal execution.

**Roles.** Each role pairs one authority with a list of actions it is allowed to take. Roles have a stable ID, so you can add, update, or remove them without touching the others.

**Authorities.** A role can be controlled by:

- Ed25519 keys (standard Solana keypairs)
- secp256k1 keys (Ethereum style signers)
- secp256r1 keys (passkeys)
- Another program, for programmatic control

Each key type also has a session variant for short lived, delegated access. Keys can be rotated and revoked onchain.

**Actions.** Actions are the permissions attached to a role. They include:

- Full access, or full access without authority management
- SOL and token spend limits, with optional recurring windows
- Limits scoped to a specific destination
- Allowlists for specific programs
- Program scoped balance tracking
- Staking limits
- Sub-account creation and management
- Authority management and recovery

**Sub-accounts.** A wallet can create sub-accounts that hold their own funds and sign on their own, under a role's control. They are useful for isolating balances per user, per strategy, or per agent.

**Recovery.** Root can grant recovery permissions to other roles, so a lost key does not mean a lost wallet.

## What you can build

- **Automated and recurring payments.** Subscriptions with onchain spend limits and clear boundaries.
- **Agentic wallets.** Give agents scoped authority: what they can spend, where, and for how long.
- **Embedded consumer wallets.** No seed phrases and no gas prompts.
- **High velocity trading.** Delegated session keys for market makers and solvers.
- **Neobanks.** Programmable accounts with deterministic policies.

## Repository layout

| Directory | Crate | What it is |
| --- | --- | --- |
| `program` | `swig` | The onchain Solana program |
| `state` | `swig-state` | Account layouts, authorities, and actions |
| `interface` | `swig-interface` | Instruction builders for the program |
| `instructions` | `swig-compact-instructions` | Compact instruction encoding |
| `assertions` | `swig-assertions` | Assertion helpers used by the program |
| `no-padding` | `no-padding` | Derive macro for padding free structs |
| `rust-sdk` | `swig-sdk` | Rust SDK for building and sending Swig transactions |
| `cli` | `swig-cli` | Command line tool for managing Swig wallets |
| `docs` | | Rust SDK guides and program diagrams |
| `audits` | | Published security assessments |

## SDKs and services

The program in this repo is the foundation. Most teams build on one of these instead of calling it directly.

- **[TypeScript SDK](https://github.com/anagrambuild/swig-ts)** for working with the protocol from TypeScript and JavaScript.
- **[Developer SDK](https://github.com/anagrambuild/swig-developer-sdk)** for the hosted Swig API, in TypeScript and Python. The API prepares wallet transactions, your app signs them, and Swig can sponsor the fees so your users never see a gas prompt.
- **[Rust SDK](docs/rust-sdk/rust-sdk.md)** in this repo, for Rust services and tooling.

Swig also offers hosted infrastructure for teams that want to ship faster: a developer API, gasless transactions through a managed paymaster, a dashboard, and more coming soon. Visit [onswig.com](https://onswig.com) to learn more, or reach out to talk about integrating smart wallets.

## Building

You need Rust 1.96.1 (pinned in `rust-toolchain.toml`) and `cargo-build-sbf` 4.0.0.

```bash
cargo install cargo-build-sbf --version 4.0.0 --locked
cargo build-sbf --arch v3 --tools-version v1.53
```

The program binary is written to `target/deploy/swig.so`.

## Testing

Install [cargo-nextest](https://nexte.st/docs/installation/from-source/), then run the main suite:

```bash
cargo build-sbf --arch v3 --tools-version v1.53
cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast
```

To run the `ProgramScope` tests, build and test with the `program_scope_test` feature:

```bash
cargo build-sbf --arch v3 --tools-version v1.53 --features=program_scope_test
cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=program_scope_test
```

The stake tests need a local validator. They require Agave CLI 4.2.2, which matches CI. Start the validator with `./validator.sh` in another terminal, then run:

```bash
cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=stake_tests --test-threads=1
```

The tests use `http://127.0.0.1:8899` by default. Set `SWIG_TEST_RPC_URL` to point at a validator on another port.

### Test dependencies

The program and Rust SDK tests pin `litesvm` and `litesvm-token` to `0.16.0`. The lockfile selects Agave 4.2.2 and solana-sbpf 0.21.1 for v3 execution, so keep `Cargo.lock` checked in.

`LiteSVM::new()` uses its bundled mainnet feature set and loads the bundled Token program at `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`. The WSOL rent tests use that same program. Its starting clock is not slot zero, so sign test payloads with `get_sysvar::<Clock>().slot`.

The bundled p-token program includes `SyncNative` reserve refreshes and rent checks, so test setup must fund new accounts to the rent minimum. After changing the pin, run the WSOL regressions and every feature suite. The pin is there for reproducible tests and says nothing about future mainnet deployments.

## Security

Published audits:

- [Accretion, Swig audit (2025)](audits/2025-accretion-anagram-swig-audit-A25ANA2.pdf)
- [Halborn, Swig Wallet Assessment executive summary (August 2026)](audits/2026-halborn-swig-wallet-assessment-executive-summary.pdf)

Each report lists the commits it covers and the scope of remediation.

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Community

- X: [@onswig](https://x.com/onswig)
- Telegram: [t.me/onswig](https://t.me/onswig)
- Blog: [blog.onswig.com](https://blog.onswig.com)

## License

Copyright (C) 2025 Anagram Ltd.

Swig is licensed under the GNU Affero General Public License v3.0. You can get a copy of the license at https://www.gnu.org/licenses/agpl-3.0.txt.

Unless required by applicable law or agreed to in writing, software distributed under the license is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
