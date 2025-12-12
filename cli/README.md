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

#### Create Sub-Account

Create a sub-account for the wallet:

```bash
swig create-sub-account --swig-id <ID>
```

Create multiple sub-accounts using the index parameter (0-254):

```bash
swig create-sub-account --swig-id <ID> --sub-account-index 1
swig create-sub-account --swig-id <ID> --sub-account-index 2
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

When adding authorities, you can specify their permissions:

- `all` - Full access to all operations
- `sol` - Permission to transfer SOL (with optional limits)

Multiple permissions can be specified using commas:

```bash
--permissions all,sol
```

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
