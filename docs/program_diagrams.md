# Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│                           SWIG SOLANA PROGRAM                         │
│                                                                       │
│   Program ID: swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB             │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│                         PROGRAM ENTRY POINTS                          │
│                                                                       │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐  │
│  │ process_instruct│   │ execute()       │   │ process_action()    │  │
│  │ ion()           │   │                 │   │                     │  │
│  │                 │   │ - Classify      │   │ - Dispatch to       │  │
│  │ - Entrypoint    │   │   accounts      │   │   instruction       │  │
│  │ - Setup context │   │ - Process       │   │   handlers based on │  │
│  │                 │   │   instructions  │   │   instruction type  │  │
│  └─────────────────┘   └─────────────────┘   └─────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│                     ACCOUNT CLASSIFICATION SYSTEM                     │
│                                                                       │
│  ┌─────────────────────────┐  ┌─────────────────────────────────────┐ │
│  │ AccountClassification   │  │ classify_account()                  │ │
│  │                         │  │                                     │ │
│  │ - ThisSwig              │  │ - Determines account type based on  │ │
│  │ - SwigTokenAccount      │  │   account owner and data structure  │ │
│  │ - SwigStakingAccount    │  │ - Enforces program constraints      │ │
│  │ - None                  │  │                                     │ │
│  └─────────────────────────┘  └─────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│                          INSTRUCTION HANDLERS                         │
│                                                                       │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌─────┐  │
│  │ CreateV1       │  │ AddAuthorityV1 │  │ SignV1         │  │ ... │  │
│  │                │  │                │  │                │  │     │  │
│  │ - Initialize   │  │ - Add new      │  │ - Authenticate │  │     │  │
│  │   Swig account │  │   authority    │  │ - Process      │  │     │  │
│  │ - Set initial  │  │   to Swig      │  │   embedded     │  │     │  │
│  │   authority    │  │ - Set          │  │   instructions │  │     │  │
│  │                │  │   permissions  │  │                │  │     │  │
│  └────────────────┘  └────────────────┘  └────────────────┘  └─────┘  │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│                          AUTHENTICATION SYSTEM                        │
│                                                                       │
│  ┌────────────────────┐  ┌────────────────────┐                       │
│  │ Ed25519            │  │ Secp256k1          │                       │
│  │ Authentication     │  │ Authentication     │                       │
│  │                    │  │                    │                       │
│  │ - Verify ed25519   │  │ - Verify secp256k1 │                       │
│  │   signatures       │  │   signatures       │                       │
│  └────────────────────┘  └────────────────────┘                       │
└───────────────────────────────────────────────────────────────────────┘
```

# Accounts

```
┌──────────────────────────────────────────────────────────────────────┐
│                       SWIG ACCOUNT STRUCTURE                         │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ Swig Account                                                  │   │
│  │                                                               │   │
│  │  - discriminator: u8 (SwigAccount)                            │   │
│  │  - id: [u8; 13]                                               │   │
│  │  - bump: u8                                                   │   │
│  │  - roles: Vec<Role>                                           │   │
│  │                                                               │   │
│  │  PDA derivation: ["swig", id, bump]                           │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                │                                     │
│                                ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ Role                                                          │   │
│  │                                                               │   │
│  │  - size: usize                                                │   │
│  │  - authority_type: AuthorityType (Ed25519 or Secp256k1)       │   │
│  │  - start_slot: u64                                            │   │
│  │  - end_slot: u64                                              │   │
│  │  - authority_data: Vec<u8> (public key for verification)      │   │
│  │  - actions: Vec<Action> (permissions for this role)           │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                │                                     │
│                                ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ Action                                                        │   │
│  │                                                               │   │
│  │  - All                                                        │   │
│  │  - ManageAuthority                                            │   │
│  │  - Tokens { action: TokenAction }                             │   │
│  │  - Token { key, action }                                      │   │
│  │  - Sol { action: SolAction }                                  │   │
│  │  - Program { key }                                            │   │
│  └───────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

# Instruction Flow & Interactions

## CreateV1

```
┌─────────────────────────┐
│ Client                  │
│                         │
│ - Creates transaction   │
│   with CreateV1         │
│   instruction           │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ CreateV1 Instruction    │
│                         │
│ - id: [u8; 13]          │
│ - bump: u8              │
│ - initial_authority     │
│ - start_slot, end_slot  │
│ - authority_data        │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Program Processor       │
│                         │
│ 1. Validate system owner│
│ 2. Check zero balance   │
│ 3. Verify PDA derivation│
│ 4. Create Swig structure│
│ 5. Allocate space       │
│ 6. Initialize account   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Result                  │
│                         │
│ - New Swig wallet with  │
│   initial authority     │
└─────────────────────────┘

## AddAuthorityV1
┌─────────────────────────┐
│ Client                  │
│                         │
│ - Creates transaction   │
│   with AddAuthorityV1   │
│   instruction           │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ AddAuthorityV1          │
│ Instruction             │
│                         │
│ - new authority type    │
│ - authority data        │
│ - permissions           │
│ - validity period       │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Program Processor       │
│                         │
│ 1. Validate signer      │
│ 2. Verify permissions   │
│ 3. Create new role      │
│ 4. Add role to Swig     │
│    account              │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Result                  │
│                         │
│ - Swig wallet with      │
│   additional authority  │
└─────────────────────────┘
```

## SignV1 (Transaction Excecution)

```
┌─────────────────────────┐
│ Client                  │
│                         │
│ - Creates transaction   │
│   with SignV1           │
│   instruction           │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ SignV1 Instruction      │
│                         │
│ - role_id               │
│ - authority_payload     │
│ - instruction_payload   │
│  (embedded instructions)│
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Program Processor       │
│                         │
│ 1. Validate Swig account│
│ 2. Load SignV1 data     │
│ 3. Lookup role by ID    │
│ 4. Authenticate         │
│    (Ed25519/Secp256k1)  │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Permission Check        │
│                         │
│ 1. Parse instruction    │
│    payload              │
│ 2. For each instruction:│
│    - Check if allowed   │
│    - Verify resource    │
│      permissions        │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Instruction Execution   │
│                         │
│ 1. Prepare accounts     │
│ 2. Create CPI calls     │
│ 3. Execute instructions │
│    with Swig PDA signer │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Result                  │
│                         │
│ - Executed transactions │
│   on behalf of Swig     │
└─────────────────────────┘
```

## Authentication Mechanism

```
┌──────────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION FLOW                           │
│                                                                  │
│  ┌────────────────┐                                              │
│  │ Client         │                                              │
│  │                │                                              │
│  │ - Signs payload│                                              │
│  │   with private │                                              │
│  │   key          │                                              │
│  └────────┬───────┘                                              │
│           │                                                      │
│           ▼                                                      │
│  ┌────────────────┐     ┌────────────────┐    ┌───────────────┐  │
│  │ Program        │     │ Authority Type │    │ Verification  │  │
│  │                │     │                │    │ Method        │  │
│  │ - Receives     │────►│ - Ed25519      │───►│ - Ed25519     │  │
│  │   signed       │     │   or           │    │   instruction │  │
│  │   payload      │     │ - Secp256k1    │    │   or          │  │
│  │                │     │                │    │ - Secp256k1   │  │
│  └────────────────┘     └────────────────┘    │   verification│  │
│                                               └───────┬───────┘  │
│                                                       │          │
│                                                       ▼          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Validation Result                                          │  │
│  │                                                            │  │
│  │ - Success: Continue with instruction execution             │  │
│  │ - Failure: Return authentication error                     │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Permission System

```
┌───────────────────────────────────────────────────────────────────┐
│                         PERMISSION SYSTEM                         │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ Action Hierarchy                                           │   │
│  │                                                            │   │
│  │ - All (Unrestricted access to all resources)               │   │
│  │   │                                                        │   │
│  │   ├─► ManageAuthority (Can modify authorities)             │   │
│  │   │                                                        │   │
│  │   ├─► Token Resources                                      │   │
│  │   │    │                                                   │   │
│  │   │    ├─► Tokens { All }                                  │   │
│  │   │    ├─► Tokens { Manage(amount) }                       │   │
│  │   │    └─► Tokens { Temporal(amount, window, last) }       │   │
│  │   │                                                        │   │
│  │   ├─► SOL Resources                                        │   │
│  │   │    │                                                   │   │
│  │   │    ├─► Sol { All }                                     │   │
│  │   │    ├─► Sol { Manage(amount) }                          │   │
│  │   │    └─► Sol { Temporal(amount, window, last) }          │   │
│  │   │                                                        │   │
│  │   └─► Program { key } (Can call specific program)          │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ Permission Checking                                        │   │
│  │                                                            │   │
│  │ 1. Match instruction program ID with allowed programs      │   │
│  │ 2. For token operations:                                   │   │
│  │    - Check token mint against permitted tokens             │   │
│  │    - Verify transaction amount against limits              │   │
│  │    - For temporal limits, check time windows               │   │
│  │ 3. For SOL operations:                                     │   │
│  │    - Verify lamport amount against limits                  │   │
│  │    - For temporal limits, check time windows               │   │
│  └────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

## Program Interaction w/ External Programs

```
┌───────────────────────────────────────────────────────────────────┐
│                 PROGRAM INTEGRATION (CPI CALLS)                   │
│                                                                   │
│  ┌─────────────────┐       ┌─────────────────┐                    │
│  │ Swig Program    │       │ External        │                    │
│  │                 │       │ Programs        │                    │
│  │ - Processes     │──────►│                 │                    │
│  │   SignV1        │       │ - Token Program │                    │
│  │ - Authenticates │       │ - System Program│                    │
│  │ - Checks        │       │ - Stake Program │                    │
│  │   permissions   │       │ - Any program   │                    │
│  │ - Prepares CPI  │       │   specified in  │                    │
│  │  with PDA signer│       │   instructions  │                    │
│  └─────────────────┘       └─────────────────┘                    │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Cross-Program Invocation (CPI)                              │  │
│  │                                                             │  │
│  │ 1. SignV1 handler parses embedded instructions              │  │
│  │ 2. For each instruction:                                    │  │
│  │    - Maps required accounts                                 │  │
│  │    - Verifies permissions                                   │  │
│  │    - Invokes instruction with PDA signer                    │  │
│  │ 3. Returns success or error for entire transaction batch    │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

# Security Model

```
┌───────────────────────────────────────────────────────────────────┐
│                         SECURITY MODEL                            │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ Multi-Authority Model                                      │   │
│  │                                                            │   │
│  │ - Multiple authorities with different capabilities         │   │
│  │ - Each authority restricted by role permissions            │   │
│  │ - Time-limited authorities                                 │   │
│  │ - Multiple signature schemes (Ed25519, Secp256k1)          │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ Resource Access Control                                    │   │
│  │                                                            │   │
│  │ - Token-specific permissions                               │   │
│  │ - Amount-limited permissions                               │   │
│  │ - Time-window spending limits                              │   │
│  │ - Program-specific call permissions                        │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ Account Validation                                         │   │
│  │                                                            │   │
│  │ - Classification of all accounts at entry point            │   │
│  │ - Ownership checks                                         │   │
│  │ - PDA derivation validation                                │   │
│  │ - Data structure validation                                │   │
│  └────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```
