# SWIG Solana Wallet Protocol

## Building

1. You must have the Agave toolchain of at least version 2.2.1 and its requirements installed. See [https://docs.anza.xyz/cli/install](https://docs.anza.xyz/cli/install) for more info.
2. To build, run `cargo build-sbf`. This will output the program binary file to `target/deploy/swig.so`.

## Testing

1. Install cargo-nextest, it's the better way to run tests. See [https://nexte.st/docs/installation/from-source/](https://nexte.st/docs/installation/from-source/) for more info.
2. Run the general test suite with `cargo build-sbf && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast`
3. Run the tests covering `ProgramScope` with `cargo build-sbf --features=program_scope_test && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=program_scope_test`
4. Run the tests covering Stake actions by running `cargo build-sbf --features=stake_tests && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=stake_tests`

The program and Rust SDK tests share exact workspace pins for `litesvm` and
`litesvm-token` at `0.11.0`. `LiteSVM::new()` enables the p-token feature and loads
the bundled Token program at `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` for all
tests. The WSOL rent tests use that same program; no separate Token binary is
committed or loaded by those tests. Keep `Cargo.lock` to preserve the dependency
checksums.

LiteSVM 0.11 includes the `SyncNative` reserve-refresh behavior and stricter rent
checks. Test setup must fund new accounts to the rent minimum. After changing the
pin, run the WSOL regressions and all feature suites. The bundled program is a
reproducible test dependency; its pin does not assert identity with future
mainnet deployments.

## V2 sub-account addresses

V2 sub-accounts bind to the parent **Swig config public key**, rather than its
wallet ID. Derive the state PDA from
`["sub-account-v2-state-address", swig_config_pubkey, subacc_id_le_u32]` and the
asset PDA from `["sub-account-v2-address", swig_config_pubkey, subacc_id_le_u32]`.
Creation derives and validates both canonical PDAs on-chain and stores their
bumps. Subsequent operations use the stored bumps without a canonical-parent
PDA search.

The state remains 72 bytes, with discriminator `3`, state and asset bumps at
offsets 1 and 2, and the parent config public key at bytes 8–39. Legacy ID-based
V2 state (discriminator `2`) is rejected; this change does not migrate it.
The new seed namespaces also separate asset addresses from legacy V2 accounts.
Program and V2 clients must be upgraded together.

V2 creation builders no longer accept bump arguments. The instruction still
has a 16-byte header, but bytes 8–15 are now reserved and must be zero, as must
the padding at bytes 2–3. Callers supply the canonical PDA accounts; they cannot
select the stored bumps. Existing fixture call sites use this updated contract.

## Audit

Swig has been independently auditted by Accretion with plans to undergo additional audits. A copy of the audit report can be shared upon request.

## License

Copyright (C) 2025 Anagram Ltd.

This software, Swig, is licensed under the GNU Affero General Public License v3.0.

You may obtain a copy of the License at:
https://www.gnu.org/licenses/agpl-3.0.txt

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
