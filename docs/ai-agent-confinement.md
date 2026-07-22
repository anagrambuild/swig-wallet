# AI Agent Trade Confinement

## Overview

Swig's agent confinement model lets AI agents execute trades on any venue while
bounding losses through post-execution enforcement. Rather than restricting
which instructions an agent can submit (which is brittle and venue-specific),
Swig validates outcomes after CPI execution completes.

Three defense layers work together:

| Layer | Mechanism | What It Prevents |
|---|---|---|
| Slippage Oracle | Ratio validation (input/output BPS check) | Excessive slippage per trade |
| Spending Limits | Absolute SOL and token caps | Unbounded cumulative losses |
| Hash Integrity | SHA256 snapshot comparison pre/post CPI | Unauthorized account mutations |

## Architecture

### Transaction Layout

A confined agent trade uses two top-level instructions:

```
IX 0: SlippageOracle::ValidateTrade(input_amount, min_output_amount, min_bps)
      accounts: [swig_config, swig_wallet_address]

IX 1: Swig::SignV2(role_id) -> inner CPI instructions
      ProgramExec authenticates against IX 0
```

### Execution Flow

1. **IX 0** -- The SlippageOracle program validates that `min_output_amount >=
   input_amount * min_bps / 10000`. It receives the Swig config and wallet
   address as its first two accounts. The instruction succeeds or the
   transaction aborts.

2. **IX 1** -- Swig's `SignV2` processor runs:
   - **Stack height check**: Verifies `SignV2` is at stack height 1 (top-level
     only, cannot be called via CPI).
   - **ProgramExec authentication**: Looks at the preceding instruction (IX 0),
     confirms it was executed by the expected oracle program with the expected
     discriminator, and that accounts[0] and accounts[1] match the Swig config
     and wallet address.
   - **Pre-CPI snapshots**: Computes SHA256 hashes of all writable account data
     (excluding mutable balance fields) and their owners.
   - **CPI execution**: Executes the agent's inner instructions, signing with
     the Swig wallet PDA.
   - **Post-CPI enforcement**: Re-hashes accounts and compares against
     snapshots. Checks spending limits against observed balance changes.

## Setting Up an Agent Role

Use `AgentRoleConfig` from `swig-sdk` to build the authority, serialized data,
and permission actions in one call:

```rust
use swig_sdk::agent_role::{AgentRoleConfig, AgentProgramPermission, AgentTokenLimit};

let config = AgentRoleConfig {
    oracle_program_id: oracle_pubkey.to_bytes(),
    oracle_discriminator: vec![0x76, 0x61, 0x6c, 0x74, 0x72, 0x61, 0x64, 0x65],
    sol_limit: Some(1_000_000_000),         // 1 SOL absolute cap
    sol_recurring_limit: None,              // or Some((amount, window_slots))
    token_limits: vec![
        AgentTokenLimit {
            mint: usdc_mint.to_bytes(),
            amount: 100_000_000,            // 100 USDC absolute cap
            recurring_window: None,
        },
    ],
    program_permission: AgentProgramPermission::Any,
    session_max_length: None,               // or Some(slots) for session keys
};

let (auth_type, auth_data, actions) = config.build();
// auth_type:  AuthorityType::ProgramExec (or ProgramExecSession if session_max_length is set)
// auth_data:  serialized ProgramExecAuthority bytes
// actions:    Vec<ClientAction> containing all permissions

// Register with the wallet:
// wallet.add_authority(auth_type, &auth_data, actions)
```

### `AgentProgramPermission` Variants

| Variant | Behavior |
|---|---|
| `Any` | Adds `ProgramAll` -- agent can CPI into any program |
| `Curated` | Adds `ProgramCurated` -- only programs on the curated allowlist |
| `Specific(vec![...])` | Adds one `Program` action per pubkey -- explicit allowlist |

### Session Keys

Set `session_max_length: Some(slot_count)` to produce a `ProgramExecSession`
authority instead of `ProgramExec`. Session keys expire after `slot_count`
slots, giving the agent time-bounded access without requiring authority removal.

## Permission Combinations

| Permission | Type | Purpose |
|---|---|---|
| `ProgramAll` | Program | Allow CPI to any program |
| `ProgramCurated` | Program | Allow CPI to curated programs only |
| `Program` | Program | Allow CPI to a single specific program |
| `SolLimit` | Spending | Absolute SOL spending cap (lifetime) |
| `SolRecurringLimit` | Spending | SOL spending cap that resets every N slots |
| `TokenLimit` | Spending | Absolute token spending cap per mint (lifetime) |
| `TokenRecurringLimit` | Spending | Token spending cap per mint, resets every N slots |
| `ProgramScope` | Tracking | Track balance changes on arbitrary accounts by field offset |
| Session keys | Access | Time-bound agent access (slot-based expiry) |

Typical confined agent setup: `ProgramAll` + `SolLimit` + one or more
`TokenLimit` entries, bound to a `ProgramExec` authority referencing the
SlippageOracle.

## Security Properties

**Post-execution hash verification.** Before CPI, `SignV2` computes SHA256
hashes of each writable account's data (excluding known mutable balance fields)
concatenated with the account owner. After CPI, it recomputes and compares. Any
unauthorized modification -- changed owner, altered non-balance fields, injected
data -- causes `AccountDataModifiedUnexpectedly` and the transaction fails.

**Outcome-based spending limits.** Limits are enforced AFTER CPI execution by
measuring actual balance deltas, not by inspecting instruction arguments. This
means limits work regardless of which DEX or program the agent calls.

**Top-level only.** `SignV2` checks `sol_get_stack_height() == 1`, ensuring it
cannot be invoked via CPI. This prevents a malicious program from calling Swig
on behalf of the agent.

**ProgramExec cannot target Swig.** When creating a `ProgramExec` authority,
the program rejects any `program_id` that matches Swig's own program ID
(`PermissionDeniedProgramExecCannotBeSwig`). This prevents circular delegation.

**Preceding instruction validation.** `ProgramExec` authentication verifies:
- The target instruction's program ID matches the configured oracle
- The instruction data starts with the configured discriminator prefix
- The instruction's first two accounts are the Swig config and wallet address
- The target instruction index is strictly before the current instruction

## Limitations

- **Spending limits are one-sided bounds.** They cap losses but do not guarantee
  execution quality. An agent could make a bad trade that stays within limits.

- **Without the oracle, no ratio enforcement.** Spending limits alone cap
  absolute amounts but cannot enforce input/output ratios. The SlippageOracle is
  required for per-trade slippage protection.

- **Oracle parameters are agent-controlled.** In the current design the agent
  chooses `input_amount`, `min_output_amount`, and `min_bps` when constructing
  the ValidateTrade instruction. The oracle validates internal consistency
  (output >= input * bps / 10000) but does not enforce a minimum `min_bps`
  value. A malicious agent could set `min_bps = 0` to bypass ratio checks while
  still satisfying the oracle.

- **ProgramScope tracks absolute amounts, not ratios.** `ProgramScope` can
  observe balance changes on arbitrary accounts by byte offset, but it measures
  absolute deltas, not input/output ratios.

- **Balance field exclusions are type-specific.** The hash integrity system
  excludes known balance fields (token account bytes 64-72, stake account bytes
  184-192). Programs with balance fields at other offsets need `ProgramScope`
  configuration to be tracked correctly.

## SlippageOracle Instruction Format

**Program ID:** `EQ2rR75Y9nzQVSVBC4Fb8p7p8xVdRsaAxdNYBLiGTZjp`

### ValidateTrade

**Discriminator:** `[0x76, 0x61, 0x6c, 0x74, 0x72, 0x61, 0x64, 0x65]` (ASCII
"valtrade")

**Accounts:**

| Index | Account | Writable | Signer | Description |
|---|---|---|---|---|
| 0 | swig_config | No | No | The Swig account (config PDA) |
| 1 | swig_wallet_address | No | No | The Swig wallet address PDA |

**Instruction Data (after 8-byte discriminator):**

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | u64 | input_amount | Amount of input tokens (lamports/microtoken units) |
| 8 | 8 | u64 | min_output_amount | Minimum acceptable output amount |
| 16 | 2 | u16 | min_bps | Minimum basis points (e.g., 9500 = 95%) |

**Validation logic:**

```
required_min = input_amount * min_bps / 10000
if min_output_amount < required_min:
    error SlippageExceeded
```

**Error Codes:**

| Code | Name | Description |
|---|---|---|
| 0 | SlippageExceeded | `min_output_amount` is below the required minimum |
| 1 | InvalidInstruction | Unrecognized discriminator or data too short (< 18 bytes after discriminator) |
| 2 | InvalidAccountCount | Fewer than 2 accounts provided |
| 3 | InvalidSwigAccount | Reserved for future Swig account validation |
| 4 | ArithmeticOverflow | Multiplication overflow in BPS calculation |
