# Instruction Builder Documentation

The `SwigInstructionBuilder` is a fundamental component of the Swig SDK that handles the creation and management of Solana instructions for the Swig protocol.

## Overview

The instruction builder provides low-level functionality for creating various types of instructions needed to interact with Swig wallets on the Solana blockchain.

## Core Components

### AuthorityManager

```rust
pub enum AuthorityManager {
    Ed25519(Pubkey),
    Secp256k1(Box<[u8]>, Box<dyn Fn(&[u8]) -> [u8; 65]>),
    Ed25519Session(CreateEd25519SessionAuthority),
    Secp256k1Session(CreateSecp256k1SessionAuthority, Box<dyn Fn(&[u8]) -> [u8; 65]>),
}
```

The `AuthorityManager` enum represents different types of signing authorities supported by the Swig protocol.

### SwigInstructionBuilder

```rust
pub struct SwigInstructionBuilder {
    swig_id: [u8; 32],
    swig_account: Pubkey,
    authority_manager: AuthorityManager,
    payer: Pubkey,
    role_id: u32,
}
```

## Core Functions

### Creating a New Instance

```rust
pub fn new(
    swig_id: [u8; 32],
    authority_manager: AuthorityManager,
    payer: Pubkey,
    role_id: u32,
) -> Self
```

Creates a new instance of the instruction builder with the specified parameters.

### Building a Swig Account

```rust
pub fn build_swig_account(&self) -> Result<Instruction, SwigError>
```

Creates an instruction to initialize a new Swig account on-chain.

### Signing Instructions

```rust
pub fn sign_instruction(
    &mut self,
    instructions: Vec<Instruction>,
    current_slot: Option<u64>,
) -> Result<Vec<Instruction>, SwigError>
```

Creates signed instructions for the provided transaction instructions.

## Authority Management

### Adding Authorities

```rust
pub fn add_authority_instruction(
    &mut self,
    new_authority_type: AuthorityType,
    new_authority: &[u8],
    permissions: Vec<ClientPermission>,
    current_slot: Option<u64>,
) -> Result<Instruction, SwigError>
```

Creates an instruction to add a new authority with specified permissions.

### Removing Authorities

```rust
pub fn remove_authority(
    &mut self,
    authority_to_remove_id: u32,
    current_slot: Option<u64>,
) -> Result<Instruction, SwigError>
```

Creates an instruction to remove an existing authority.

### Replacing Authorities

```rust
pub fn replace_authority(
    &mut self,
    authority_to_replace_id: u32,
    new_authority_type: AuthorityType,
    new_authority: &[u8],
    permissions: Vec<ClientPermission>,
    current_slot: Option<u64>,
) -> Result<Vec<Instruction>, SwigError>
```

Creates instructions to replace an existing authority with a new one.

## Session Management

### Creating Sessions

```rust
pub fn create_session_instruction(
    &self,
    session_key: Pubkey,
    session_duration: u64,
    current_slot: Option<u64>,
) -> Result<Instruction, SwigError>
```

Creates an instruction to create a new session for temporary authority delegation.

## Utility Functions

### Getting the Swig Account

```rust
pub fn get_swig_account(&self) -> Result<Pubkey, SwigError>
```

Returns the public key of the Swig account.

### Getting the Role ID

```rust
pub fn get_role_id(&self) -> u32
```

Returns the current role ID of the Swig account.

### Switching Authority

```rust
pub fn switch_authority(&mut self, role_id: u32, authority: Pubkey) -> Result<(), SwigError>
```

Switches the current authority and role ID.

## Examples

### Creating a New Swig Account

```rust
let instruction_builder = SwigInstructionBuilder::new(
    swig_id,
    AuthorityManager::Ed25519(authority_pubkey),
    payer_pubkey,
    0
);

let create_ix = instruction_builder.build_swig_account()?;
```

### Adding a New Authority

```rust
let add_authority_ix = instruction_builder.add_authority_instruction(
    AuthorityType::Ed25519,
    new_authority_bytes,
    vec![Permission::All],
    Some(current_slot)
)?;
```
