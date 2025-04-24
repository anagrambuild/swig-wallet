# Swig Rust SDK Documentation

Welcome to the Swig Rust SDK documentation. This SDK provides a comprehensive set of tools for interacting with the Swig protocol on the Solana blockchain.

## 📚 Components

### [Instruction Builder](./instruction-builder.md)

The instruction builder component provides low-level functionality for creating and managing Swig instructions. It handles:

- Creating Swig accounts
- Managing authorities
- Building transaction instructions
- Session management
- Authority type handling (Ed25519, Secp256k1)

### [Wallet SDK](./wallet.md)

The wallet SDK provides high-level abstractions for interacting with Swig wallets. It offers:

- Wallet creation and management
- Transaction signing
- Authority management
- Session handling
- Balance checking
- Permission management

## 🚀 Quick Start

```rust
use swig_sdk::{SwigWallet, AuthorityManager};

// Create a new wallet instance
let wallet = SwigWallet::new(
    swig_id,
    authority_manager,
    fee_payer,
    authority,
    rpc_url,
)?;

// Add a new authority
wallet.add_authority(
    AuthorityType::Ed25519,
    new_authority,
    vec![Permission::All]
)?;

// Sign a transaction
wallet.sign(instructions, None)?;
```

## 📋 Features

- **Multi-signature Support**: Create and manage multi-signature wallets
- **Flexible Authority Types**: Support for Ed25519 and Secp256k1
- **Session Management**: Create and manage temporary signing sessions
- **Permission System**: Granular control over authority permissions
- **Transaction Building**: Easy-to-use transaction building interface

## 🔗 Related Links

- [GitHub Repository](https://github.com/swig-wallet)
- [Examples](./examples)
