# GitHub Actions Workflows

This directory contains GitHub Actions workflows for automating build, test, and quality assurance processes for the Swig Solana program.

## Workflows

### Build and Test (`build-and-test.yml`)

This workflow builds and tests the Solana program and other Rust components:

- Triggered on pushes to `main` and pull requests to `main`
- Uses Rust version specified in `rust-toolchain.toml` (currently 1.82.0)
- Installs Solana tools (version 1.18.4)
- Builds the Solana program using `cargo build-sbf`
- Runs all Rust tests with `cargo nextest`
- Runs Solana program tests with `cargo test-sbf`
- Generates JUnit test reports for easy visualization of test results

### Lint and Code Quality (`lint.yml`)

This workflow performs code quality checks:

- Triggered on pushes to `main` and pull requests to `main`
- Uses Rust version specified in `rust-toolchain.toml` (currently 1.82.0)
- Checks code formatting with `cargo fmt`
- Runs Clippy linting with `cargo clippy`

## Configuration

The workflows use environment variables to make configuration easier:

- `RUST_VERSION`: The Rust toolchain version (currently 1.82.0)
- `SOLANA_VERSION`: The Solana tools version (currently 2.1.0)

To update these versions, simply modify the environment variables at the top of each workflow file.

## Caching

The workflows use caching to speed up builds:

- Cargo dependencies are cached using the `actions/cache` action
- Compilation is accelerated using `sccache` for faster builds

## Test Reporting

Test results are reported using:

- `cargo-nextest` for running tests and generating JUnit XML reports
- `mikepenz/action-junit-report` for displaying test results in the GitHub Actions UI
- Test artifacts are uploaded for later inspection

## Local Testing

You can test these workflows locally using the `test_gh_actions.sh` script in the root directory. This script uses the [act](https://github.com/nektos/act) tool to run GitHub Actions workflows locally.

```bash
# Run all workflows with push event
./test_gh_actions.sh

# Run a specific workflow
./test_gh_actions.sh --workflow build-and-test.yml

# Run with pull_request event
./test_gh_actions.sh --event pull_request

# Debug mode with verbose output
./test_gh_actions.sh --verbose
```

The script handles different event types correctly and provides detailed output about each workflow run. It also includes troubleshooting features to help identify issues.

For more information on local testing, see the [LOCAL_TESTING.md](../LOCAL_TESTING.md) file. 