# Swig Program Architecture (v1.4.0, current)

## Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│                          SWIG SOLANA PROGRAM                          │
│                                                                       │
│  Program ID: swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB              │
│  Version:    1.4.0                                                    │
│  License:    AGPL-3.0                                                 │
│  Framework:  pinocchio (zero-copy, no-alloc)                          │
└───────────────────────────────────────────────────────────────────────┘
```

Swig is a role-based smart wallet protocol for Solana. It enables multiple
authorities with fine-grained permissions to operate a shared wallet through
cross-program invocations (CPI), supporting four signature schemes
(with session variants) and 21 permission types.

---

## Workspace Structure

```
swig-wallet/
├── program/               On-chain BPF program (entrypoint + instruction handlers)
├── state/                 Account state, roles, authorities, actions (shared types)
├── instructions/          Compact instruction encoding/decoding for CPI payloads
├── assertions/            On-chain assertion macros and validation helpers
├── no-padding/            Proc-macro: ensures #[repr(C)] structs have no padding
├── interface/             Client-side instruction builders (CreateInstruction, etc.)
├── rust-sdk/              High-level Rust SDK (SwigWallet, SwigInstructionBuilder)
├── cli/                   CLI application for wallet management
└── test-program-authority/  Test helper program for ProgramExec authority testing
```

### Dependency Hierarchy

```
                    ┌──────────────┐
                    │     cli      │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   rust-sdk   │
                    └──┬───────┬───┘
                       │       │
              ┌────────▼──┐  ┌─▼──────────┐
              │ interface │  │   state     │
              └──┬──┬──┬──┘  └──┬──────┬──┘
                 │  │  │        │      │
    ┌────────────▼┐ │ ┌▼────────▼─┐  ┌─▼──────────┐
    │ instructions│ │ │  program   │  │ no-padding │
    └─────────────┘ │ └─────┬──┬──┘  └────────────┘
                    │       │  │
              ┌─────▼───┐   │ ┌▼───────────┐
              │  state   │   │ │ assertions │
              └──────────┘   │ └────────────┘
                             │
                      ┌──────▼───────┐
                      │ instructions │
                      └──────────────┘
```

---

## Program Entry Points

```
┌───────────────────────────────────────────────────────────────────────┐
│                         PROGRAM ENTRY POINTS                          │
│                                                                       │
│  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐   │
│  │ process_          │   │ execute()        │   │ process_action() │   │
│  │  instruction()    │   │                  │   │                  │   │
│  │                   │   │ - Classify all   │   │ - Dispatch to    │   │
│  │ - Lazy entrypoint │   │   accounts       │   │   instruction    │   │
│  │ - Minimal setup   │   │ - Build account  │   │   handler by     │   │
│  │                   │   │   classifications│   │   discriminator  │   │
│  └──────────────────┘   └──────────────────┘   └──────────────────┘   │
│                                                                       │
│  Uses pinocchio lazy_entrypoint! for minimal compute overhead         │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Account Model

### Account Types and PDAs

```
┌───────────────────────────────────────────────────────────────────────┐
│                          ACCOUNT MODEL (V2)                           │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Swig Config Account (PDA: ["swig", id])                         │  │
│  │                                                                 │  │
│  │ Stores configuration, roles, and permissions.                   │  │
│  │ V2 wallets use swig_wallet_address for execution assets.        │  │
│  │ (Legacy v1 balances may exist until migration transfer.)        │  │
│  │                                                                 │  │
│  │  discriminator  : u8       = 1 (SwigConfigAccount)              │  │
│  │  bump           : u8       PDA bump seed                        │  │
│  │  id             : [u8; 32] Unique wallet identifier             │  │
│  │  roles          : u16      Number of active roles               │  │
│  │  role_counter   : u32      Monotonic ID counter for new roles   │  │
│  │  wallet_bump    : u8       Wallet address PDA bump              │  │
│  │  _padding       : [u8; 7]  Alignment padding                   │  │
│  │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │  │
│  │  [variable-length role data...]                                 │  │
│  │                                                                 │  │
│  │  Total header: 48 bytes (Swig::LEN)                             │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                         │                                             │
│           ┌─────────────┼──────────────┐                              │
│           ▼             ▼              ▼                               │
│  ┌────────────────┐ ┌────────────┐ ┌──────────────────────────────┐   │
│  │ Swig Wallet    │ │ Sub-Account│ │ Token Accounts               │   │
│  │ Address (PDA)  │ │ (PDA)      │ │ (owned by Swig Wallet Addr)  │   │
│  │                │ │            │ │                              │   │
│  │ ["swig-wallet- │ │ ["sub-     │ │ SPL Token accounts with     │   │
│  │  address",     │ │  account", │ │ authority set to the        │   │
│  │  swig_key]     │ │  swig_id,  │ │ swig_wallet_address PDA     │   │
│  │                │ │  role_id]  │ │                              │   │
│  │ Holds SOL and  │ │            │ │                              │   │
│  │ is the signer  │ │ Isolated   │ │                              │   │
│  │ for all CPIs   │ │ SOL balance│ │                              │   │
│  └────────────────┘ └────────────┘ └──────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

### Account Classification System

At the start of every instruction, the program classifies all transaction
accounts to track balances and enforce post-execution integrity checks.

```
┌───────────────────────────────────────────────────────────────────────┐
│                    ACCOUNT CLASSIFICATION SYSTEM                      │
│                                                                       │
│  AccountClassification enum:                                          │
│                                                                       │
│  ┌──────────────────┐  Swig config account with initial lamports      │
│  │ ThisSwigV2       │  balance snapshot for integrity checking         │
│  ├──────────────────┤                                                  │
│  │ SwigWalletAddress│  The wallet address PDA that holds assets        │
│  ├──────────────────┤                                                  │
│  │ SwigTokenAccount │  SPL token account: tracks balance + spent       │
│  ├──────────────────┤                                                  │
│  │ SwigStakeAccount │  Stake account: tracks state + balance + spent   │
│  ├──────────────────┤                                                  │
│  │ ProgramScope     │  Tracked account for program scope permission:   │
│  │                  │  role_index, balance (u128), spent (u128)        │
│  ├──────────────────┤                                                  │
│  │ SwigSubAccount   │  Sub-account classification used by dedicated    │
│  │                  │  sub-account instruction paths                   │
│  ├──────────────────┤                                                  │
│  │ None             │  Unrelated account                               │
│  └──────────────────┘                                                  │
└───────────────────────────────────────────────────────────────────────┘
```

### Role Structure

Roles are stored as variable-length entries in the Swig account data
following the 48-byte header.

```
┌───────────────────────────────────────────────────────────────────────┐
│                          ROLE STRUCTURE                                │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Position (16 bytes, #[repr(C, align(8))])                       │  │
│  │                                                                 │  │
│  │  authority_type    : u16   Maps to AuthorityType enum           │  │
│  │  authority_length  : u16   Byte length of authority data        │  │
│  │  num_actions       : u16   Number of actions in this role       │  │
│  │  padding           : u16   Alignment padding                   │  │
│  │  id                : u32   Unique role ID (from role_counter)   │  │
│  │  boundary          : u32   Byte offset to end of role data     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                         │                                             │
│                         ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Authority Data (variable length)                                │  │
│  │                                                                 │  │
│  │  The concrete authority struct (Ed25519, Secp256k1, etc.)       │  │
│  │  Size depends on AuthorityType (see Authentication section)     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                         │                                             │
│                         ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Actions (variable number, each 8-byte header + variable data)   │  │
│  │                                                                 │  │
│  │  ┌─────────────────────────────────────────────────────────┐    │  │
│  │  │ Action (8 bytes header, #[repr(C, align(8))])            │    │  │
│  │  │                                                         │    │  │
│  │  │  action_type : u16   Maps to Permission enum            │    │  │
│  │  │  length      : u16   Length of action-specific data     │    │  │
│  │  │  boundary    : u32   Offset to next action              │    │  │
│  │  └─────────────────────────────────────────────────────────┘    │  │
│  │  [action-specific data follows...]                              │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Instructions (16 variants)

```
┌───────────────────────────────────────────────────────────────────────┐
│                     INSTRUCTION SET (SwigInstruction)                  │
│                     Discriminator: u16                                 │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Wallet Lifecycle                                                 │ │
│  │                                                                  │ │
│  │  0  CreateV1               Initialize new Swig wallet + wallet   │ │
│  │                            address PDA                           │ │
│  │ 15  CloseSwigV1            Close the Swig account entirely       │ │
│  │ 14  CloseTokenAccountV1    Close a zero-balance token account    │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Authority Management                                             │ │
│  │                                                                  │ │
│  │  1  AddAuthorityV1         Add a new role/authority              │ │
│  │  2  RemoveAuthorityV1      Remove an existing role               │ │
│  │  3  UpdateAuthorityV1      Update an existing role               │ │
│  │  5  CreateSessionV1        Create a temporary session key        │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Transaction Execution                                            │ │
│  │                                                                  │ │
│  │  4  DeprecatedSignV1       DEPRECATED (returns error)            │ │
│  │ 11  SignV2                 Sign and execute via CPI              │ │
│  │                            (main signing instruction)            │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Sub-Accounts                                                     │ │
│  │                                                                  │ │
│  │  6  CreateSubAccountV1     Create a sub-account PDA              │ │
│  │  7  WithdrawFromSubAccountV1  Withdraw from sub-account to       │ │
│  │                               wallet address                     │ │
│  │  9  SubAccountSignV1       Execute from a sub-account            │ │
│  │ 10  ToggleSubAccountV1     Enable/disable a sub-account          │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Migration (V1 -> V2)                                             │ │
│  │                                                                  │ │
│  │ 12  MigrateToWalletAddressV1  Migrate old account format         │ │
│  │ 13  TransferAssetsV1          Transfer assets to wallet address  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Authentication System

Four signature schemes, each with a session-key variant (8 authority types total).

```
┌───────────────────────────────────────────────────────────────────────┐
│                       AUTHENTICATION SYSTEM                           │
│                       AuthorityType enum (u16)                        │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ 1  Ed25519             Standard Solana keypair (32-byte pubkey)  │ │
│  │ 2  Ed25519Session      Ed25519 + session key support             │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ 3  Secp256k1           Ethereum-compatible ECDSA (33-byte       │ │
│  │                        compressed pubkey + signature odometer)   │ │
│  │ 4  Secp256k1Session    Secp256k1 + session key support           │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ 5  Secp256r1           Passkeys/WebAuthn (33-byte compressed    │ │
│  │                        pubkey via Solana Secp256r1 precompile)   │ │
│  │ 6  Secp256r1Session    Secp256r1 + session key support           │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ 7  ProgramExec         Delegate auth to a preceding instruction  │ │
│  │                        from another program (program_id +        │ │
│  │                        instruction data prefix matching)         │ │
│  │ 8  ProgramExecSession  ProgramExec + session key support         │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
┌───────────────────────────────────────────────────────────────────────┐
│                       AUTHENTICATION FLOW                             │
│                                                                       │
│   Client                                                              │
│     │                                                                 │
│     │  Signs payload with private key or triggers                     │
│     │  a preceding program instruction                                │
│     │                                                                 │
│     ▼                                                                 │
│   ┌─────────────────────┐                                             │
│   │ Authority Dispatch  │                                             │
│   │                     │                                             │
│   │ Match authority_type│                                             │
│   │ of the role         │                                             │
│   └──┬──┬──┬──┬─────────┘                                             │
│      │  │  │  │                                                       │
│      ▼  │  │  │                                                       │
│   Ed25519       Verify signer matches stored pubkey.                  │
│   (Native)      Check account_info.is_signer == true.                 │
│      │  │  │                                                          │
│      │  ▼  │                                                          │
│   Secp256k1     Verify via Secp256k1 precompile instruction.          │
│   (EVM)         Replay protection via signature odometer.             │
│                 Message is keccak256-based over signed payload data.  │
│                 Max signature age: 60 slots.                          │
│      │     │                                                          │
│      │     ▼                                                          │
│   Secp256r1     Verify via Secp256r1 precompile instruction.          │
│   (Passkeys)    Supports raw signatures and WebAuthn format           │
│                 (Huffman-encoded origin URLs, authenticator data).     │
│                 Replay protection via signature odometer.              │
│                 Max signature age: 60 slots.                          │
│            │                                                          │
│            ▼                                                          │
│   ProgramExec   Verify a preceding instruction was from the expected  │
│   (Delegate)    program with matching instruction data prefix.        │
│                 First two accounts must be swig config + wallet.      │
│                 Cannot delegate to the Swig program itself.           │
│                                                                       │
│   Session variants: After initial auth, create a temporary Ed25519    │
│   session key with a slot-based expiration. Subsequent transactions   │
│   authenticate with the session key (cheaper, no precompile needed).  │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Permission System (21 types)

```
┌───────────────────────────────────────────────────────────────────────┐
│                  PERMISSION SYSTEM (Permission enum, u16)              │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Full Access                                                      │ │
│  │                                                                  │ │
│  │  7  All                  Unrestricted access to everything       │ │
│  │ 15  AllButManageAuthority  All except authority/subaccount mgmt  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Authority & Account Management                                   │ │
│  │                                                                  │ │
│  │  8  ManageAuthority      Add/remove/update roles                 │ │
│  │  9  SubAccount           Create/manage sub-accounts              │ │
│  │ 20  CloseSwigAuthority   Close token accounts and swig account   │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ SOL Permissions                                                  │ │
│  │                                                                  │ │
│  │  1  SolLimit                  Absolute SOL spend limit           │ │
│  │  2  SolRecurringLimit         Time-windowed SOL spend limit      │ │
│  │ 16  SolDestinationLimit       SOL limit to specific destination  │ │
│  │ 17  SolRecurringDestinationLimit  Recurring SOL limit per dest   │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Token Permissions                                                │ │
│  │                                                                  │ │
│  │  5  TokenLimit                Absolute token spend limit         │ │
│  │  6  TokenRecurringLimit       Time-windowed token spend limit    │ │
│  │ 18  TokenDestinationLimit     Token limit to specific dest       │ │
│  │ 19  TokenRecurringDestinationLimit  Recurring token limit/dest   │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Staking Permissions                                              │ │
│  │                                                                  │ │
│  │ 10  StakeLimit            Absolute stake operation limit         │ │
│  │ 11  StakeRecurringLimit   Time-windowed stake operation limit    │ │
│  │ 12  StakeAll              Unrestricted stake operations          │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Program Permissions                                              │ │
│  │                                                                  │ │
│  │  3  Program               CPI to a specific program only        │ │
│  │  4  ProgramScope          Track balance field changes in         │ │
│  │                           arbitrary program accounts             │ │
│  │ 13  ProgramAll            Unrestricted CPI to any program       │ │
│  │ 14  ProgramCurated        CPI only to a curated program set     │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

### Permission Enforcement Model

```
┌───────────────────────────────────────────────────────────────────────┐
│                     PERMISSION ENFORCEMENT                            │
│                                                                       │
│  Permissions are checked POST-EXECUTION by comparing account          │
│  snapshots taken before and after CPI execution.                      │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Pre-Execution                                                    │ │
│  │                                                                  │ │
│  │  1. Snapshot all classified accounts via SHA256 hash             │ │
│  │     - Token accounts: hash all data EXCEPT balance field         │ │
│  │     - Stake accounts: hash all data EXCEPT balance field         │ │
│  │     - ProgramScope:   hash all data EXCEPT configured field      │ │
│  │     - Swig config:    hash all data + owner                      │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Execution                                                        │ │
│  │                                                                  │ │
│  │  2. Execute each CPI instruction                                 │ │
│  │  3. After each instruction, compute spent deltas for:            │ │
│  │     - Token accounts (balance decrease)                          │ │
│  │     - Stake accounts (balance decrease)                          │ │
│  │     - ProgramScope accounts (balance field change)               │ │
│  │  4. Track total SOL spent from wallet address lamport changes    │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Post-Execution                                                   │ │
│  │                                                                  │ │
│  │  5. Verify all account hashes match (no unauthorized changes)    │ │
│  │  6. If role has All permission -> skip limit checks              │ │
│  │  7. Otherwise enforce limits:                                    │ │
│  │     - SOL: check SolLimit / SolRecurringLimit /                  │ │
│  │            SolDestinationLimit / SolRecurringDestinationLimit     │ │
│  │     - Tokens: check destination limits first, then fall back     │ │
│  │              to TokenLimit / TokenRecurringLimit                  │ │
│  │     - Stakes: check StakeLimit / StakeRecurringLimit             │ │
│  │     - ProgramScope: run balance tracking logic                   │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

---

## SignV2 Flow (Main Transaction Execution)

```
┌───────────────────────────────────────────────────────────────────────┐
│                        SignV2 EXECUTION FLOW                          │
│                                                                       │
│  Client                                                               │
│    │                                                                  │
│    │  Builds transaction with:                                        │
│    │  - SignV2Args: instruction(u16=11), payload_len(u16), role_id(u32)│
│    │  - Compact instruction payload (embedded CPI instructions)       │
│    │  - Authority payload (signature / session key / program ref)     │
│    │                                                                  │
│    ▼                                                                  │
│  Phase 1: VALIDATION                                                  │
│    │                                                                  │
│    │  1. check_stack_height(1) -- must be top-level (no CPI into Swig)│
│    │  2. Verify account classifications (ThisSwigV2 + SwigWalletAddr) │
│    │  3. Parse SignV2Args from instruction data                       │
│    │  4. Load Swig account, verify discriminator                      │
│    │  5. Look up role by role_id                                      │
│    │                                                                  │
│    ▼                                                                  │
│  Phase 2: AUTHENTICATION                                              │
│    │                                                                  │
│    │  6. Get current clock slot                                       │
│    │  7. If session-based: authenticate_session(payload, slot)        │
│    │     Otherwise:        authenticate(payload, slot)                │
│    │                                                                  │
│    ▼                                                                  │
│  Phase 3: PRE-EXECUTION SNAPSHOTS                                     │
│    │                                                                  │
│    │  8. Create InstructionIterator over compact payload               │
│    │  9. Build PDA signer seeds for swig_wallet_address               │
│    │ 10. Check if role has All / AllButManageAuthority permission      │
│    │ 11. SHA256 hash all writable classified accounts                  │
│    │     (excluding mutable balance fields)                           │
│    │                                                                  │
│    ▼                                                                  │
│  Phase 4: CPI EXECUTION                                               │
│    │                                                                  │
│    │ 12. For each embedded instruction:                                │
│    │     a. If not All: verify CPI program permission                 │
│    │        (ProgramAll / ProgramCurated / Program)                   │
│    │     b. Execute CPI with swig_wallet_address as PDA signer        │
│    │     c. Track SOL spent from wallet address                       │
│    │     d. Update token/stake/scope spent deltas                     │
│    │                                                                  │
│    ▼                                                                  │
│  Phase 5: POST-EXECUTION PERMISSION ENFORCEMENT                       │
│    │                                                                  │
│    │ 13. If All permission -> return Ok                                │
│    │ 14. For each classified account:                                  │
│    │     - Verify hash integrity (no unauthorized data changes)       │
│    │     - Enforce SOL/token/stake/scope spending limits               │
│    │     - Update on-chain limit counters (amount spent, timestamps)  │
│    │                                                                  │
│    ▼                                                                  │
│  Result: Executed transaction(s) on behalf of the Swig wallet         │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Compact Instruction Format

CPI instructions are encoded in a space-efficient binary format with
deduplicated account indexes to minimize transaction size.

```
┌───────────────────────────────────────────────────────────────────────┐
│                    COMPACT INSTRUCTION WIRE FORMAT                     │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ [1 byte]  num_instructions                                      │  │
│  │                                                                 │  │
│  │ For each instruction:                                           │  │
│  │   [1 byte]  program_id_index    (index into accounts list)      │  │
│  │   [1 byte]  num_accounts                                       │  │
│  │   [N bytes] account_indexes     (1 byte each, N = num_accounts) │  │
│  │   [2 bytes] data_length         (u16 LE)                        │  │
│  │   [M bytes] instruction_data    (M = data_length)               │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  Client-side: compact_instructions() deduplicates accounts across     │
│  all inner instructions, converting pubkeys to u8 indexes.            │
│  Max accounts: 254                                                    │
│                                                                       │
│  On-chain: InstructionIterator parses the payload, reconstructs       │
│  AccountMeta entries, and executes each CPI with PDA signer.          │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Sub-Account System

```
┌───────────────────────────────────────────────────────────────────────┐
│                        SUB-ACCOUNT SYSTEM                             │
│                                                                       │
│  Sub-accounts provide isolated SOL balances per role.                 │
│                                                                       │
│  PDA: ["sub-account", swig_id, role_id]                               │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Operations                                                       │ │
│  │                                                                  │ │
│  │  CreateSubAccountV1       Derive and initialize sub-account PDA  │ │
│  │                           Requires SubAccount permission         │ │
│  │                                                                  │ │
│  │  SubAccountSignV1         Execute CPI from sub-account           │ │
│  │                           (sub-account is the signer PDA)        │ │
│  │                                                                  │ │
│  │  WithdrawFromSubAccountV1 Move SOL from sub-account back to      │ │
│  │                           the main swig_wallet_address            │ │
│  │                                                                  │ │
│  │  ToggleSubAccountV1       Enable or disable a sub-account        │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Cross-Program Invocation (CPI)

```
┌───────────────────────────────────────────────────────────────────────┐
│                    PROGRAM INTEGRATION (CPI)                          │
│                                                                       │
│  ┌─────────────────┐          ┌──────────────────┐                    │
│  │ Swig Program    │          │ External Programs │                   │
│  │                 │          │                   │                    │
│  │ - Authenticates │──CPI────►│ - System Program  │                   │
│  │ - Checks perms  │          │ - SPL Token       │                   │
│  │ - Prepares PDA  │          │ - Stake Program   │                   │
│  │   signer seeds  │          │ - Any program     │                   │
│  └─────────────────┘          └──────────────────┘                    │
│                                                                       │
│  The swig_wallet_address PDA is the signer for all CPIs.              │
│  The swig config account itself does NOT sign CPIs.                   │
│                                                                       │
│  Special handling:                                                    │
│  - System Program Transfer to system-owned PDAs: proper CPI           │
│  - System Program Transfer to program-owned accounts: direct          │
│    lamport manipulation (backwards compatibility)                     │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Security Model

```
┌───────────────────────────────────────────────────────────────────────┐
│                          SECURITY MODEL                               │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Multi-Authority RBAC                                             │ │
│  │                                                                  │ │
│  │  - Multiple roles with independent permissions                   │ │
│  │  - Monotonic role IDs prevent ID reuse                           │ │
│  │  - 4 signature schemes (Ed25519, Secp256k1, Secp256r1,          │ │
│  │    ProgramExec) each with session variant                        │ │
│  │  - Session keys with slot-based expiration                       │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Replay Protection                                                │ │
│  │                                                                  │ │
│  │  - Secp256k1: signature odometer (counter must increment)        │ │
│  │  - Secp256r1: signature odometer + slot-age check (60 slots)     │ │
│  │  - Ed25519: native Solana signer verification                    │ │
│  │  - ProgramExec: instruction introspection (no replay concern)    │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ CPI Safety                                                       │ │
│  │                                                                  │ │
│  │  - Stack height check: SignV2 must be top-level (not via CPI)    │ │
│  │  - ProgramExec cannot delegate to the Swig program itself        │ │
│  │  - Post-execution SHA256 integrity verification on all           │ │
│  │    classified accounts (detects unauthorized data changes)        │ │
│  │  - Token account authority must be swig_wallet_address            │ │
│  │  - Token account delegate presence is rejected                   │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Account Validation                                               │ │
│  │                                                                  │ │
│  │  - All accounts classified at entry                              │ │
│  │  - PDA derivation verification                                   │ │
│  │  - Ownership checks                                              │ │
│  │  - Discriminator validation (SwigConfigAccount = 1)              │ │
│  │  - Rent-exemption enforcement on wallet address                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │ Zero-Copy Safety                                                 │ │
│  │                                                                  │ │
│  │  - no-padding proc-macro validates #[repr(C)] struct layouts     │ │
│  │  - Transmutable / TransmutableMut traits for safe zero-copy      │ │
│  │    access to on-chain data without serialization                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Error Codes

```
┌───────────────────────────────────────────────────────────────────────┐
│                         ERROR CODE RANGES                             │
│                                                                       │
│  0-46       SwigError             General program/account errors       │
│  1000-1007  SwigStateError        Account/state data validation        │
│  2000-2002  InstructionError      Compact instruction parsing          │
│  3000-3039  SwigAuthenticateError Authentication + permission checks  │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Build and Test

```
Build:   cargo build-sbf
         Outputs: target/deploy/swig.so
         build.rs auto-generates idl.json via shank

Test:    cargo build-sbf && cargo nextest run --config-file nextest.toml \
           --profile ci --all --workspace --no-fail-fast

         Feature-gated tests:
           --features=program_scope_test   (ProgramScope coverage)
           --features=stake_tests          (Stake action coverage)

Toolchain: Rust 1.84.0 (via rust-toolchain.toml)
           Agave toolchain >= 2.2.1
```
