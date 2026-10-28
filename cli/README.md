# SWIG CLI

A command-line interface for interacting with SWIG wallets on Solana.

## Features

- Interactive mode with guided prompts
- Command mode for scripting and automation
- Rich terminal output with colors and progress indicators
- Support for Ed25519 and Secp256k1 authorities
- Comprehensive wallet management commands
- Integration with Solana CLI config

## Installation

1. Make sure you have Rust and Cargo installed
2. Clone the repository
3. Build the CLI:

```bash
cargo build --release
```

4. The binary will be available at `target/release/swig`

## Usage

The CLI can be used in two modes:

### Interactive Mode

Run the CLI in interactive mode:

```bash
swig -i
```

This will present a menu-driven interface with the following options:

- Create New Wallet
- Add Authority
- Remove Authority
- View Wallet
- List Authorities
- Check Balance

### Command Mode

For scripting and automation, use the command mode:

#### Create a New Wallet

```bash
swig create --root ed25519 --authority <PUBKEY> [--swig-id <ID>]
```

#### Add an Authority

```bash
swig add-authority \
    --authority-type ed25519 \
    --authority <PUBKEY> \
    --swig-id <ID> \
    --permissions all,sol
```

#### Remove an Authority

```bash
swig remove-authority --swig-id <ID> --authority <PUBKEY>
```

#### View Wallet Details

```bash
swig view --swig-id <ID>
```

#### List Authorities

```bash
swig list-authorities --swig-id <ID>
```

#### Check Balance

```bash
swig balance --swig-id <ID>
```

### Global Options

These options can be used with any command:

- `-c, --config <PATH>` - Path to Solana config file
- `-k, --keypair <PATH>` - Path to keypair file
- `-u, --rpc-url <URL>` - RPC URL
- `-i, --interactive` - Use interactive mode

You must provide either:

1. `--rpc-url` and `--keypair`, or
2. `--config` pointing to a Solana CLI config file

## Authority Types

The CLI supports multiple authority types:

- `ed25519` - Standard Ed25519 keypairs (recommended)
- `secp256k1` - Secp256k1 keypairs for Ethereum/Bitcoin compatibility
- `ed25519-session` - Temporary session-based Ed25519 authorities
- `secp256k1-session` - Temporary session-based Secp256k1 authorities

## Permissions

When adding or updating authorities, each permission is a JSON object with a
`type` field, for example:

- `{"type":"all"}` - Full access to all operations
- `{"type":"sol","amount":1000000000}` - Transfer up to an amount of SOL (add
  `"recurring":{"window":<slots>}` for a recurring limit)
- `{"type":"manageAuthorizationLocks","maxDurationSlots":216000}` - Place
  authorization locks within the role's own spending limits, for at most
  `maxDurationSlots` slots

Pass several permissions by repeating the flag (JSON is not split on commas):

```bash
--permissions '{"type":"manageAuthorizationLocks","maxDurationSlots":216000}' \
--permissions '{"type":"sol","amount":1000000000}'
```

## Authorization Locks

An authorization lock reserves part of the wallet's SOL or token balance until an
expiry slot. While the lock is active, no role (including `All`) can spend that
asset below the reserved amount, and only the role that created the lock can
release it early. Every lock needs the `manageAuthorizationLocks` permission,
and no lock can last longer than that role's `maxDurationSlots`, even for `All`.
Roles that also have `All` or `AllButManageAuthority` can lock up to the
wallet's balance. Other roles can lock any token up to their own spending limit
for it. A role cannot change its own `maxDurationSlots`; another manager sets
it (the root role can set its own).

```bash
# Reserve 1.5 SOL for the next 400 slots
swig add-authorization-lock --swig-id <ID> --amount 1500000000 --duration-slots 400

# Reserve tokens in the wallet's associated token account until a given slot
swig add-authorization-lock --swig-id <ID> --mint <MINT> --amount 600 --expiry-slot <SLOT>

# List active locks (add --all to include expired, unpruned locks)
swig list-authorization-locks --swig-id <ID>

# Release your own lock, or prune an expired one (needs All, AllButManageAuthority,
# ManageAuthority, or manageAuthorizationLocks)
swig remove-authorization-lock --swig-id <ID> --lock-id <LOCK_ID>
```

All three commands also take `--authority-type`, `--authority`, `--authority-kp`
(and `--fee-payer` for the write commands), or fall back to the saved default
authority. In interactive mode, use the "Authorization Locks" menu.

## Examples

1. Create a new wallet with Ed25519 authority:

```bash
swig create \
    --root ed25519 \
    --authority 5KL2xJ6nTxgqxcp5HpZCKPsG9QYhYdqyPKxE8BqPFh1h
```

2. Add a Secp256k1 authority with SOL transfer permission:

```bash
swig add-authority \
    --authority-type secp256k1 \
    --authority 0x742d35Cc6634C0532925a3b844Bc454e4438f44e \
    --swig-id my-wallet \
    --permissions sol
```

3. View wallet details in interactive mode:

```bash
swig -i
# Then select "View Wallet" from the menu
```

## Development

### Project Structure

```
cli-x/
├── src/
│   └── main.rs    # Main CLI implementation
├── Cargo.toml     # Dependencies and package info
└── README.md      # This file
```

### Adding New Commands

1. Add a new variant to the `Command` enum in `main.rs`
2. Implement the command's execution logic
3. Add the command to both interactive and command modes
4. Update the documentation

### Testing

Run the tests:

```bash
cargo test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
