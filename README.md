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

## Isolation guard

`IsolationGuard::new` snapshots outer signers. Call `snapshot(index)`
for each relevant writable account before executing CPIs, then call
`validate()` after execution. The guard retains the account list it captured. SignV2 and both
sub-account signing paths use this lifecycle. The guard is bounded local scratch;
there is no new wire format or stored wallet state.

Validation protects personal token balances, lamports, program ownership, token
owner/delegate/close authority, and the existing supported authority-bearing
account layouts. Incoming SOL and tokens are permitted, including legacy WSOL
`SyncNative` reserve refreshes. Token-2022 extension bytes remain immutable;
transfer-fee bookkeeping support is a separate change.
Personal SOL wrapping is not an allowed spending exception.

The exception for personal SOL decreases is **new-account rent**: an initially
empty System account must become a rent-exempt, non-executable account owned by
another program. Its contribution is the final rent requirement minus its
pre-existing lamports. This supports nested and idempotent ATA creation, including
prefunded ATAs, and new account keypairs signing their own creation. Existing
accounts' deposits and funding above rent do not increase the allowed decrease.

This is a check of final state. The sum of signers' net decreases is bounded by
the sum of eligible creation rent; it does not attribute each rent payment to a
particular signer or prove how a signature was used inside a nested CPI. A
forwarded signer retains ordinary Solana signer privileges. Unknown programs'
authority semantics are not inferred. Strict purpose-limited co-signing would
require a separate execution or authorization design.

## Authority management and recovery

Only root (role 0) may grant `ReplaceAuthority(0)`, whether through
`AddAuthorityV1` or the `AddActions` / `ReplaceAll` operations of
`UpdateAuthorityV1`. Grants targeting non-root roles retain their existing
administrative permission checks. Only root may update its own permissions.

These restrictions apply when granting permissions or updating root; existing
recovery execution, signer replacement, and non-root role management stay the
same. Existing recovery grants remain valid after upgrade.

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
