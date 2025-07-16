# PRD: Sub-Account Functionality for Swig Wallet

## 1. Overview

Swig Wallet currently allows for a single wallet with role-based permissions. This PRD outlines the implementation of a hierarchical wallet structure via sub-accounts, enabling a primary Swig wallet to create and manage multiple child Swig wallets (sub-accounts) each with their own role-based permissions and actions.

## 2. Product Goals

-   Enable creation of hierarchical wallet structures
-   Allow the parent wallet to create and manage sub-accounts
-   Permit sub-accounts to have their own distinct authorities and permissions
-   Maintain the existing zero-copy design pattern and Pinocchio integration
-   Ensure security by implementing proper authorization checks for sub-account operations

## 3. Requirements

### 3.1 Functional Requirements

1. **Sub-Account Creation**

    - Primary Swig wallet can create sub-accounts
    - Sub-accounts are Swig accounts with their own PDA addresses
    - Sub-accounts track their parent wallet address
    - Parent wallets track a list of their sub-accounts

2. **Permission Management**

    - Parent wallet can set initial permissions for sub-accounts
    - Sub-accounts can have their own specific roles and authorities
    - Parent wallet can modify or revoke sub-account permissions
    - Optional permission delegation from parent to sub-accounts

3. **Transaction Execution**

    - Sub-accounts can execute transactions based on their permissions
    - Parent wallet can execute transactions on behalf of sub-accounts
    - Transaction origin (parent or sub-account) is tracked for audit purposes

4. **Account Recovery**
    - Parent wallet can recover sub-accounts if needed
    - Parent wallet can transfer sub-account ownership

### 3.2 Technical Requirements

1. **State Management**

    - Create new zero-copy state struct `SubAccountRelationship` to track parent-child relationships
    - Extend Swig struct to track sub-account relationships
    - Implement efficient indexing for sub-account lookup

2. **Instruction Processing**

    - Add new instructions for sub-account creation and management
    - Implement permission validation for sub-account operations
    - Create handlers for all sub-account related instructions

3. **Security**
    - Ensure proper authorization checks for all sub-account operations
    - Implement parent-child relationship validation
    - Prevent circular or invalid hierarchical structures

## 4. Implementation Design

### 4.1 Data Structures

1. **Extended Swig Account**

    - Add fields to track sub-account relationships
    - Track parent relationship if account is a sub-account

2. **SubAccountRelationship**

    - Store parent-child relationship metadata
    - Track permission delegation settings

3. **SubAccountAction Permission**
    - Extend existing permission system with sub-account management capabilities

### 4.2 Instructions

1. **CreateSubAccountV1**

    - Create a new sub-account under the parent Swig wallet
    - Initialize with specified permissions

2. **ManageSubAccountV1**
    - Update sub-account permissions
    - Transfer sub-account ownership
    - Remove sub-account

### 4.3 Account Structure

1. **Parent Swig Account**

    - PDA with seeds ["swig", parent_id]
    - Stores list of sub-account public keys

2. **Sub-Account**
    - PDA with seeds ["swig", "sub", parent_id, sub_id]
    - References parent wallet
    - Has independent roles and authorities

## 5. Technical Implementation Plan

1. Update state-x module with sub-account relationship tracking
2. Implement new instructions in program module
3. Add sub-account permission validation in the action module
4. Update interface and rust-sdk to support sub-account operations
5. Add comprehensive tests for all sub-account functionality

## 6. Success Metrics

1. Sub-accounts can be created and managed successfully
2. Hierarchical permission system works correctly
3. Transactions can be executed through the hierarchy
4. All operations adhere to permission constraints
5. Zero-copy design is maintained throughout
