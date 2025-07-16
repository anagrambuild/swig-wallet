# SWIG - Solana Smart Wallet

## Overview

SWIG (Solana Web Infrastructure Gateway) is a smart wallet protocol built on the Solana blockchain. It provides a secure and customizable wallet solution with advanced features like multi-signature control, fine-grained permission management, programmable transaction approval, and sub-accounts.

## Program ID

`swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB`

## Key Components

### Core Crates

The SWIG wallet is comprised of several interconnected crates:

1. **program**: The main Solana program implementing the smart wallet functionality
2. **state-x**: State management for the wallet, defining account structures and data types
3. **instructions**: Compact instruction handling for transaction execution
4. **assertions**: Utility crate for validation and assertions
5. **interface**: Client interface for interacting with the SWIG program

## Architecture

### Wallet Structure

SWIG implements a role-based wallet with versatile control mechanisms:

-   **Roles and Authorities**: Each SWIG wallet can have multiple authorities with different roles
-   **Actions and Permissions**: Fine-grained control through configurable actions
-   **Sub-accounts**: Isolated accounts managed by the main wallet
-   **Programmable Control**: Supports different signing mechanisms including Ed25519 and Secp256k1

### Account Types

1. **Swig Account**: The main wallet account
2. **SwigSubAccount**: Sub-account owned by the main wallet

### Authority Types

SWIG supports multiple authentication methods:

-   Ed25519 (standard Solana keys)
-   Ed25519Session (time-limited session keys)
-   Secp256k1 (Ethereum-compatible keys)
-   Secp256k1Session (time-limited Ethereum-compatible session keys)

### Permission System

The wallet implements a flexible permission system with various action types:

-   **SolLimit**: Limits on SOL transfers
-   **SolRecurringLimit**: Recurring limits on SOL transfers
-   **TokenLimit**: Limits on token transfers
-   **TokenRecurringLimit**: Recurring limits on token transfers
-   **Program**: Permission to interact with specific programs
-   **ProgramScope**: Granular permissions for specific program accounts
-   **All**: Full wallet permissions
-   **ManageAuthority**: Permission to manage wallet authorities
-   **SubAccount**: Permission to manage sub-accounts
-   **StakeLimit**: Limits on staking operations
-   **StakeRecurringLimit**: Recurring limits on staking operations
-   **StakeAll**: Full staking permissions

## Main Instructions

### Wallet Management

-   **CreateV1**: Create a new SWIG wallet
-   **SignV1**: Execute transactions through the wallet
-   **AddAuthorityV1**: Add a new authority to the wallet
-   **RemoveAuthorityV1**: Remove an existing authority
-   **CreateSessionV1**: Create a temporary session key

### Sub-account Management

-   **CreateSubAccountV1**: Create a new sub-account
-   **WithdrawFromSubAccountV1**: Withdraw funds from a sub-account
-   **SubAccountSignV1**: Execute transactions from a sub-account
-   **ToggleSubAccountV1**: Enable or disable a sub-account

## Client Interface

The interface crate provides methods for interacting with the SWIG wallet:

-   **CreateInstruction**: Create a new wallet
-   **AddAuthorityInstruction**: Add new authorities
-   **RemoveAuthorityInstruction**: Remove existing authorities
-   **SignInstruction**: Sign and execute transactions
-   **CreateSessionInstruction**: Create temporary session keys
-   **CreateSubAccountInstruction**: Create sub-accounts
-   **WithdrawFromSubAccountInstruction**: Withdraw from sub-accounts
-   **SubAccountSignInstruction**: Sign transactions with sub-accounts
-   **ToggleSubAccountInstruction**: Enable/disable sub-accounts

## Security Features

-   Role-based access control
-   Multi-signature support
-   Session key management
-   Balance and spending limits
-   Program interaction restrictions
-   On-curve public key validation

## Use Cases

-   Multi-signature wallets
-   Treasury management
-   DAO funds management
-   Controlled delegation of funds
-   Complex signing policies
-   Institutional custody solutions

## Technical Implementation

SWIG uses Solana's account model with custom discriminators and data structures. It implements optimized memory management and makes extensive use of unsafe Rust for performance within the constraints of Solana's runtime.
