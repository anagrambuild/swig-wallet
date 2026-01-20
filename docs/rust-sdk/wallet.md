# Wallet SDK Documentation

The `SwigWallet` is an abstraction for interacting with Swig wallets on chain. It provides a user-friendly interface for managing wallets, authorities, and transactions.

## Overview

The Wallet SDK builds upon the instruction builder to provide comprehensive Swig wallet management. It handles RPC communication, transaction building, and wallet state management.

## Core Components

### SwigWallet Structure

```rust
pub struct SwigWallet<'a> {
    instruction_builder: SwigInstructionBuilder,
    rpc_client: RpcClient,
    fee_payer: &'a Keypair,
    authority: &'a Keypair,
}
```

## Core Functions

### Creating a New Wallet

```rust
pub fn new(
    swig_id: [u8; 32],
    authority_manager: AuthorityManager,
    fee_payer: &'c Keypair,
    authority: &'c Keypair,
    rpc_url: String,
) -> Result<Self, SwigError>
```

Creates a new Swig wallet or initializes an existing one.

## Authority Management

### Adding Authorities

```rust
pub fn add_authority(
    &mut self,
    new_authority_type: AuthorityType,
    new_authority: &[u8],
    permissions: Vec<Permission>,
) -> Result<Signature, SwigError>
```

Adds a new authority to the wallet with specified permissions.

### Removing Authorities

```rust
pub fn remove_authority_instruction(
    &mut self,
    authority: &[u8]
) -> Result<Signature, SwigError>
```

Removes an existing authority from the wallet.

### Replacing Authorities

```rust
pub fn replace_authority(
    &mut self,
    authority_to_replace_id: u32,
    new_authority_type: AuthorityType,
    new_authority: &[u8],
    permissions: Vec<Permission>,
) -> Result<Signature, SwigError>
```

Replaces an existing authority with a new one.

## Transaction Management

### Signing Transactions

```rust
pub fn sign(
    &mut self,
    inner_instructions: Vec<Instruction>,
    alt: Option<&[AddressLookupTableAccount]>,
) -> Result<Signature, SwigError>
```

Signs and sends a transaction containing the provided instructions.

## Session Management

### Creating Sessions

```rust
pub fn create_session(
    &mut self,
    session_key: Pubkey,
    duration: u64
) -> Result<(), SwigError>
```

Creates a new session for temporary authority delegation.

## Wallet Information

### Displaying Wallet Details

```rust
pub fn display_swig(&self) -> Result<(), SwigError>
```

Displays detailed information about the wallet, including:

- Account address
- Total roles
- Balance
- Authority details
- Permissions

### Getting Wallet Balance

```rust
pub fn get_balance(&self) -> Result<u64, SwigError>
```

Returns the SOL balance of the Swig account.

### Getting Authority Permissions

```rust
pub fn get_current_authority_permissions(&self) -> Result<Vec<Permission>, SwigError>
```

Retrieves the current authority's permissions from the Swig account.

## Utility Functions

### Switching Authority

```rust
pub fn switch_authority(
    &mut self,
    role_id: u32,
    authority: Pubkey
) -> Result<(), SwigError>
```

Switches to a different authority for the wallet.

### Switching Fee Payer

```rust
pub fn switch_payer(
    &mut self,
    payer: &'c Keypair
) -> Result<(), SwigError>
```

Updates the fee payer for the wallet.

## Examples

### Creating a New Wallet

```rust
let wallet = SwigWallet::new(
    swig_id,
    AuthorityManager::Ed25519(authority_pubkey),
    &fee_payer,
    &authority,
    "https://api.mainnet-beta.solana.com".to_string(),
)?;
```

### Adding an Authority with Permissions

```rust
let signature = wallet.add_authority(
    AuthorityType::Ed25519,
    &new_authority_bytes,
    vec![
        Permission::All,
        Permission::Sol {
            amount: 1_000_000_000, // 1 SOL
            recurring: None,
        },
    ],
)?;
```

### Creating a Session

```rust
wallet.create_session(
    session_keypair.pubkey(),
    1000, // Duration in slots
)?;
```

### Signing a Transaction

```rust
let signature = wallet.sign(
    vec![transfer_instruction],
    None, // No address lookup tables
)?;
```
