# p-token Sync Native Breaking Change Migration Guide

## Issue Summary

**Reporter:** Solana Foundation (Edward Chan, Justin Blumenthal, Aaron)  
**Affected Component:** Swig client-side instruction compaction (TypeScript and Rust SDK)  
**Breaking Change:** p-token PR #138  
**Severity:** High — transactions will fail after p-token mainnet deployment

---

## Background

The Solana Foundation identified Swig transactions (e.g., `275HQ...X9xgu`) that would fail after the p-token program goes live on mainnet. This is due to a breaking change introduced in **p-token PR #138** related to the `Sync Native` instruction.

### What Changed in p-token #138

Prior to p-token #138, the SPL Token program's `SyncNative` instruction processor iterated only the **first account** and silently ignored any additional accounts passed in the instruction.

After p-token #138, the instruction processor added account validation: if a **second account exists**, it **must** be the **Rent Sysvar**. If any other account is passed as the second account, the instruction will now error.

```rust
// Example of what will FAIL after p-token #138:
let sync = Instruction {
    program_id: spl_token::ID,
    accounts: vec![
        AccountMeta::new(wsol_ata, false),
        AccountMeta::new_readonly(some_extra_account, false), // ERROR: not Rent sysvar
    ],
    data: vec![17], // SyncNative instruction data
};
```

---

## Root Cause in Swig

The issue is located in the Swig client's instruction compaction logic:

- **TypeScript:** `packages/lib/src/instructions/compactInstruction.ts`
- **Rust SDK:** `instructions/src/compact_instructions.rs` (re-exported via `swig-interface`)

During instruction compaction, the Swig client deduplicates accounts across inner instructions and converts them to indexed references. In the TypeScript implementation, an **extra account is being appended** to the `SyncNative` instruction's account list. Because this extra account is **not** the Rent Sysvar, the instruction will fail under p-token #138.

> **Note:** The on-chain Swig program itself is not at fault. The program faithfully executes the compacted inner instructions via CPI. The issue is purely in how the **client constructs** the `SyncNative` instruction before compaction.

---

## Exact Fix Required

### Option A: Remove the Extra Account (Recommended)

Since the SPL Token program historically ignored any account beyond the first for `SyncNative`, the simplest and safest fix is to ensure the `SyncNative` instruction contains **only one account**: the wSOL ATA.

```typescript
// CORRECT — only the wSOL ATA is required
const syncNativeIx = new TransactionInstruction({
  programId: TOKEN_PROGRAM_ID,
  keys: [
    { pubkey: wsolAta, isSigner: false, isWritable: true },
    // DO NOT add any extra accounts here
  ],
  data: Buffer.from([17]), // SyncNative
});
```

### Option B: Keep Extra Account but Use Rent Sysvar

If the Swig client architecture requires the extra account to remain (e.g., for indexing consistency during compaction), then the account in **slot `[1]`** must be the Rent Sysvar:

```typescript
import { SYSVAR_RENT_PUBKEY } from '@solana/web3.js';

const syncNativeIx = new TransactionInstruction({
  programId: TOKEN_PROGRAM_ID,
  keys: [
    { pubkey: wsolAta, isSigner: false, isWritable: true },      // slot [0]
    { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false }, // slot [1] — MUST be Rent
  ],
  data: Buffer.from([17]), // SyncNative
});
```

---

## Changes Required for `swig-ts`

The TypeScript client (`swig-ts`) must be updated in `packages/lib/src/instructions/compactInstruction.ts` (and any other location constructing `SyncNative` instructions) to ensure one of the following:

1. **Filter `SyncNative` accounts:** Before compaction, detect if an inner instruction is `SyncNative` (program ID equals `TOKEN_PROGRAM_ID` and first byte of data is `17`). If it has more than one account, either:
   - Truncate to only the first account (wSOL ATA), **or**
   - Verify the second account is `SYSVAR_RENT_PUBKEY`.

2. **Update compaction logic:** Ensure the compaction routine does not inadvertently append the Swig wallet address, signer accounts, or any other account to the `SyncNative` instruction's key list.

### Pseudocode for `compactInstruction.ts`

```typescript
function sanitizeSyncNative(instruction: TransactionInstruction): TransactionInstruction {
  const isSyncNative =
    instruction.programId.equals(TOKEN_PROGRAM_ID) &&
    instruction.data.length === 1 &&
    instruction.data[0] === 17;

  if (!isSyncNative) return instruction;

  // Option A: Strip all but the first account
  return new TransactionInstruction({
    programId: instruction.programId,
    keys: instruction.keys.slice(0, 1),
    data: instruction.data,
  });

  // Option B (alternative): enforce Rent sysvar at slot [1]
  // if (instruction.keys.length > 1) {
  //   const secondKey = instruction.keys[1].pubkey;
  //   if (!secondKey.equals(SYSVAR_RENT_PUBKEY)) {
  //     throw new Error('SyncNative second account must be Rent sysvar per p-token #138');
  //   }
  // }
}
```

---

## Rust SDK Considerations

The Rust `compact_instructions` function in `swig-compact-instructions` does **not** add extra accounts to inner instructions—it only deduplicates and indexes accounts that are already present. Therefore, Rust SDK users are **not** affected unless they manually construct a `SyncNative` instruction with extra accounts.

### Recommendation for Rust SDK Users

When building `SyncNative` instructions with the Rust SDK, ensure only the wSOL ATA is included:

```rust
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    sysvar::rent::ID as RENT_SYSVAR_ID,
};

// Correct — single account
let sync_native = Instruction {
    program_id: spl_token::ID,
    accounts: vec![AccountMeta::new(wsol_ata, false)],
    data: vec![17],
};

// If you MUST include a second account, it must be Rent:
let sync_native_with_rent = Instruction {
    program_id: spl_token::ID,
    accounts: vec![
        AccountMeta::new(wsol_ata, false),
        AccountMeta::new_readonly(RENT_SYSVAR_ID, false),
    ],
    data: vec![17],
};
```

---

## Impact on Existing Clients

### Who Is Affected?

- **All `swig-ts` clients** that wrap SOL via `SyncNative` and use the built-in instruction compaction.
- **Rust SDK clients** that manually append extra accounts to `SyncNative` instructions.

### What Happens After p-token Goes Live?

Any Swig transaction containing a `SyncNative` instruction with an extra account (that is not the Rent Sysvar) will:

1. Be rejected by the p-token program with an account validation error.
2. Fail the entire Swig transaction, causing a poor user experience and potential loss of transaction fees.

### Backwards Compatibility

- **Pre-p-token:** Extra accounts in `SyncNative` were silently ignored. These transactions worked.
- **Post-p-token:** Extra accounts are validated. Invalid extra accounts cause failures.
- **Fix:** Removing the extra account works on **both** pre-p-token and post-p-token environments.

---

## Testing Recommendations

1. **Unit tests:** Add a test in `swig-ts` that verifies `SyncNative` instructions have either:
   - Exactly 1 account (wSOL ATA), **or**
   - 2 accounts where the second is `SYSVAR_RENT_PUBKEY`.

2. **Integration tests:** Run end-to-end wSOL wrap/unwrap transactions against a p-token-enabled test validator (e.g., LiteSVM with p-token).

3. **Mainnet readiness:** Audit all historical Swig transactions that included `SyncNative` to confirm the fix covers all edge cases.

---

## Timeline

- **Immediate:** Update `swig-ts` and release a patch version.
- **Before p-token mainnet:** All Swig client applications must upgrade to the patched version.
- **Ongoing:** Monitor for any other SPL Token instructions affected by p-token account validation changes.

---

## References

- p-token PR #138 (SPL Token program account validation for `SyncNative`)
- Solana Foundation readiness check report (Swig transaction `275HQ...X9xgu`)
- SPL Token `SyncNative` instruction: [program ID `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`, instruction data `[17]`]
