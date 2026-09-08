# SWIG Solana Wallet Protocol

## Building

1. You must have the Agave toolchain of at least version 2.2.1 and its requirements installed. See [https://docs.anza.xyz/cli/install](https://docs.anza.xyz/cli/install) for more info.
2. To build, run `cargo build-sbf`. This will output the program binary file to `target/deploy/swig.so`.

## Testing

1. Install cargo-nextest, it's the better way to run tests. See [https://nexte.st/docs/installation/from-source/](https://nexte.st/docs/installation/from-source/) for more info.
2. Run the general test suite with `cargo build-sbf && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast`
3. Run the tests covering `ProgramScope` with `cargo build-sbf --features=program_scope_test && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=program_scope_test`
4. Run the tests covering Stake actions by running `cargo build-sbf --features=stake_tests && cargo nextest run --config-file nextest.toml --profile ci --all --workspace --no-fail-fast --features=stake_tests`

## Authority management and recovery

`All` grants unrestricted signing and administration of ordinary roles.
`ManageAuthority` grants administration without unrestricted signing. Both
permissions retain the existing prohibition on removing root (role 0).
Only root may update its own permissions. Another role may replace root's
signer only with an explicit `ReplaceAuthority(0)` permission.

Root controls recovery delegation: only root may add `ReplaceAuthority`
permissions or use `UpdateAuthorityV1` to change a role that holds them. This rule
applies to every replacement scope, including scopes targeting another recovery
role. Replacing another recovery role's signer requires root or the matching
`ReplaceAuthority(role_id)` permission. A recovery role retains its existing
permission to rotate its own signer. ProgramExec replacements still require
proof of the exact approved replacement.

An explicitly granted `SubAccountV2Create` still permits a recovery role to
create a child and receive its automatic `SubAccountV2All` permission.

Existing `ReplaceAuthority` grants remain valid after upgrade. Review those
grants before upgrading: the stored role format does not record who granted a
permission. Root may revoke and reissue recovery roles as needed. Root can still
restrict its own permissions subject to the existing last-administrator guard,
and authority managers retain their ability to remove non-root roles.

## Audit

Swig has been independently auditted by Accretion with plans to undergo additional audits. A copy of the audit report can be shared upon request.

## License

Copyright (C) 2025 Anagram Ltd.

This software, Swig, is licensed under the GNU Affero General Public License v3.0.

You may obtain a copy of the License at:
https://www.gnu.org/licenses/agpl-3.0.txt

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
