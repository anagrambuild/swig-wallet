# SWIG Solana Wallet Protocol

## Building

1. You must have the Agave toolchain of at least version 2.2.1 and its requirements installed. See [https://docs.anza.xyz/cli/install](https://docs.anza.xyz/cli/install) for more info.
2. To build, run `cargo build-sbf`. This will output the program binary file to `target/deploy/swig.so`.

## Testing

1. Install cargo-nextest, it's the better way to run tests. See [https://nexte.st/docs/installation/from-source/](https://nexte.st/docs/installation/from-source/) for more info.
2. Run the general test suite with `cargo build-sbf && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast`
3. Run the tests covering `ProgramScope` with `cargo build-sbf --features=program_scope_test && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=program_scope_test`
4. Run the tests covering Stake actions by running `cargo build-sbf --features=stake_tests && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=stake_tests`
