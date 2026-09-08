# SPL Token reserve-refresh fixture

`spl_token_sync_native.so` is the unmodified SPL Token program built from
[solana-program/token at 0087ca54bd5a5b07e1df7e1b52303529047a1186](https://github.com/solana-program/token/tree/0087ca54bd5a5b07e1df7e1b52303529047a1186).
Its `SyncNative` reads the current rent sysvar and updates both `amount` and
`is_native`. LiteSVM 0.10.0 bundles SPL Token 3.5.0, which retains the old reserve;
using that bundled binary would not exercise the compatibility change.

SHA-256: `fc88c8f9d97e5ddae8f10da43dd0a1f5f08fffa862958542e32dd3887307f760`

Built with `cargo-build-sbf 4.0.0`, platform-tools v1.53 (rustc 1.89.0), using
the upstream committed `Cargo.lock`:

```sh
git clone https://github.com/solana-program/token.git /tmp/swig-token-fixture
git -C /tmp/swig-token-fixture checkout --detach 0087ca54bd5a5b07e1df7e1b52303529047a1186
cd /tmp/swig-token-fixture
cargo build-sbf --arch v1 --manifest-path program/Cargo.toml
shasum -a 256 target/deploy/spl_token.so
```

The binary is included so the test suite has no network or build-time upstream
dependency. It is a source-built compatibility fixture, not a claim of deployed
binary identity. The upstream Apache-2.0 license is in `SPL-TOKEN-LICENSE`.

`sign_v2_wsol_rent.rs` loads this fixture under the canonical legacy Token program
ID in its own LiteSVM instance. The existing test authority program composes
ordinary `SyncNative` and `Transfer` calls to exercise one CPI observation; it
does not implement token accounting or write token state.
