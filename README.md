# SWIG Solana Wallet Protocol

## Building

1. Use the pinned host Rust 1.96.1 and install `cargo-build-sbf` 4.0.0 with `cargo install cargo-build-sbf --version 4.0.0 --locked`. Validator tests require Agave CLI 4.2.2, matching CI. Platform-tools supplies the separate SBF compiler.
2. Run `cargo build-sbf --arch v3 --tools-version v1.53`. This outputs the program binary to `target/deploy/swig.so`.

## Testing

1. Install cargo-nextest, it's the better way to run tests. See [https://nexte.st/docs/installation/from-source/](https://nexte.st/docs/installation/from-source/) for more info.
2. Run the general test suite with `cargo build-sbf --arch v3 --tools-version v1.53 && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast`
3. Run the tests covering `ProgramScope` with `cargo build-sbf --arch v3 --tools-version v1.53 --features=program_scope_test && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=program_scope_test`
4. Start the Agave 4.2.2 validator with `./validator.sh` in another terminal, then run the Stake suite with `cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=stake_tests --test-threads=1`. The tests use `http://127.0.0.1:8899` by default; set `SWIG_TEST_RPC_URL` when running an isolated validator on another port.

The program and Rust SDK tests share exact workspace pins for `litesvm` and
`litesvm-token` at `0.16.0`. The lockfile selects Agave 4.2.2 and solana-sbpf 0.21.1
for v3 execution. `LiteSVM::new()` uses its bundled mainnet feature set and loads
the bundled Token program at `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` for all
tests. The WSOL rent tests use that same program; no separate Token binary is
committed or loaded by those tests. Keep `Cargo.lock` to preserve the dependency
checksums. Its initial clock reflects the bundled mainnet feature activations;
sign test payloads with `get_sysvar::<Clock>().slot` instead of assuming slot zero.

The bundled p-token program includes `SyncNative` reserve refreshes and rent
checks. Test setup must fund new accounts to the rent minimum. After changing the
pin, run the WSOL regressions and all feature suites. The bundled program is a
reproducible test dependency; its pin does not assert identity with future
mainnet deployments.

## Isolation guard

`IsolationGuard::new` allocates empty scratch. After authentication, call
`capture_signers(pda)` once, then `snapshot(index)` for each relevant writable
account before executing any CPI. Call `validate()` after execution. The guard
retains the account list it captured. SignV2 and both sub-account signing paths
use this lifecycle. The guard is bounded local scratch; there is no new wire
format or stored wallet state.

Validation protects personal token balances, lamports, program ownership, token
owner/delegate/close authority, and the existing supported authority-bearing
account layouts. Incoming SOL and tokens are permitted, including legacy WSOL
`SyncNative` reserve refreshes and the Token-2022 fee bookkeeping described below.
Personal SOL wrapping is not an allowed spending exception.

The exception for personal SOL decreases is **new-account rent**: an initially
empty System account must become a rent-exempt, non-executable account owned by
another program. Its contribution is the final rent requirement minus its
pre-existing lamports. This supports nested and idempotent ATA creation, including
prefunded ATAs, and new account keypairs signing their own creation. Existing
accounts' deposits and funding above rent do not increase the allowed decrease.
Rent accounting captures up to eight candidate destinations. If that capacity is
exceeded, transactions that preserve personal signer balances remain supported;
transactions that need the personal rent-funding allowance are rejected.

This is a check of final state. The sum of signers' net decreases is bounded by
the sum of eligible creation rent; it does not attribute each rent payment to a
particular signer or prove how a signature was used inside a nested CPI. A
forwarded signer retains ordinary Solana signer privileges. Unknown programs'
authority semantics are not inferred. Strict purpose-limited co-signing would
require a separate execution or authorization design.

## ProgramScope spending

ProgramScope snapshots are selected after authentication from the requested
role's actions. The same role and field supply the pre-CPI balance, post-CPI
balance, integrity checks, and limit consumption. Other roles cannot supply a
baseline, and an unreadable acting-role field is an error rather than a skipped
accounting step.

## Token-2022 extension compatibility

SignV2's restricted token checks and the outer-signer isolation guard allow the
`TransferFeeAmount.withheld_amount` payload to change during a CPI. Transfer fees
can accumulate on a destination or be collected without treating those changes
as account tampering. The extension location is captured before execution; its
type, length, and all other protected account bytes remain immutable.

Wallet spending limits continue to use the ordinary token amount, which already
includes transfer fees in outgoing debits. For these Token-2022 accounts,
outer-signer token amounts and lamports must still not decrease. Withheld fees
are controlled by the mint's fee authority and are not added to the holder's
spendable balance. This policy does not authorize mutations of confidential
balances or other extension payloads.
The transfer-fee tests use the real Token-2022 program bundled with pinned
LiteSVM and the production signing instruction builders.

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
