# Program security notes

Implementation notes on how the Swig program protects wallet state during signing. These were previously in the repository README.

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

