# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SWIG is a Solana wallet protocol implementing a multi-authority smart wallet with granular permission controls. The project uses Rust for the on-chain program and React/TypeScript for the frontend.

**Security Note**: This project is undergoing audit and is NOT ready for production use.

## Common Development Commands

### Building
```bash
# Build the Solana program (requires Agave toolchain v2.2.1+)
cargo build-sbf

# Build the frontend app
cd swig-app && bun install && bun run build
```

### Testing
```bash
# Run all tests with CI profile
cargo nextest run --config-file nextest.toml --profile ci

# Run program scope tests
cargo nextest run --config-file nextest.toml --profile ci --features=program_scope_test

# Run stake tests
cargo nextest run --config-file nextest.toml --profile ci --features=stake_tests

# Run a specific test
cargo nextest run --config-file nextest.toml test_name

# Launch local validator for testing
./validator.sh
```

### Linting and Formatting
```bash
# Format Rust code (max width 100, 4 spaces, Unix newlines)
cargo fmt

# Check formatting
cargo fmt -- --check

# Frontend linting
cd swig-app && bun run lint
```

## Architecture Overview

### Core Components

1. **`program/`** - The main Solana program
   - Entry point: `src/lib.rs` defines the program ID and instruction processor
   - Instructions: `src/instruction.rs` defines all program instructions using shank
   - Actions: `src/actions/` contains the business logic for each instruction
   - Uses Pinocchio framework for low-level Solana operations

2. **`state-x/`** - State management and account structures
   - `src/swig.rs` - Main wallet account structure with authority management
   - `src/authority/` - Ed25519 and Secp256k1 authority implementations
   - `src/action/` - Permission rules for different operations (transfers, staking, etc.)
   - `src/role.rs` - Role-based access control definitions

3. **`rust-sdk/`** - Client SDK for interacting with the program
   - `src/instruction_builder.rs` - Fluent API for building instructions
   - `src/wallet.rs` - High-level wallet management interface
   - Provides both low-level instruction building and high-level wallet operations

4. **`cli-x/`** - Command-line interface
   - Supports both interactive and command modes
   - Configuration via JSON file for wallet management
   - Used for testing and administrative operations

### Key Architectural Patterns

1. **Multi-Authority System**: Wallets can have multiple authorities with different permission levels. Each authority can be either Ed25519 or Secp256k1.

2. **Permission Model**: Permissions are defined as "Actions" that specify:
   - What operations are allowed (transfer SOL, stake, etc.)
   - Limits (amount, time windows, recurring limits)
   - Scope (global, program-specific, token-specific)

3. **Account Relationships**:
   - Main wallet account (Swig) → Multiple authorities
   - Authorities → Roles → Actions (permissions)
   - Sub-accounts linked to parent accounts with delegated permissions

4. **Instruction Pattern**: Each instruction follows:
   - Validation of accounts and signatures
   - Permission checking against configured actions
   - State updates with proper serialization

### Testing Strategy

- Unit tests in each crate test individual components
- Integration tests in `program/tests/` test full instruction flows
- Uses `litesvm` for fast in-memory Solana runtime simulation
- Feature flags control test scenarios (program_scope_test, stake_tests)

### Important Files

- `program/src/instruction.rs` - All program instructions
- `state-x/src/swig.rs` - Core wallet account structure
- `rust-sdk/src/instruction_builder.rs` - SDK entry point
- `program/tests/common/mod.rs` - Test utilities and helpers