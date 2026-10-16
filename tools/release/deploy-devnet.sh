#!/usr/bin/env bash
set -euo pipefail

: "${SOLANA_RPC_URL:?SOLANA_RPC_URL is required}"
: "${PROGRAM_AUTHORITY_KEYPAIR:?PROGRAM_AUTHORITY_KEYPAIR is required}"
: "${SWIG_PROGRAM_ID:?SWIG_PROGRAM_ID is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

# The binary declares this canonical ID; a different target would be unusable.
test "$SWIG_PROGRAM_ID" = swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB
if [[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || \
   [[ ! "$RELEASE_TAG" =~ ^devnet-upgrade-[0-9]+-${SOURCE_SHA:0:12}$ ]]; then
  echo "::error::The devnet release tag must identify the source commit."
  exit 1
fi

umask 077
private_dir=$(mktemp -d "$RUNNER_TEMP/swig-devnet.XXXXXX")
trap 'rm -rf "$private_dir"' EXIT
trap 'exit 1' HUP INT TERM
printf '%s' "$PROGRAM_AUTHORITY_KEYPAIR" > "$private_dir/authority.json"
unset PROGRAM_AUTHORITY_KEYPAIR
authority=$(solana-keygen pubkey "$private_dir/authority.json" 2>/dev/null)
solana_args=(--url "$SOLANA_RPC_URL" --commitment finalized --keypair "$private_dir/authority.json")

# Reject a mainnet/testnet RPC before any GitHub or on-chain mutation.
genesis=$(solana genesis-hash "${solana_args[@]}" 2>/dev/null)
if [ "$genesis" != EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG ]; then
  echo "::error::SOLANA_RPC_URL must point to Solana devnet."
  exit 1
fi
solana program show "$SWIG_PROGRAM_ID" "${solana_args[@]}" --output json \
  > "$private_dir/program.json" 2>/dev/null
if ! jq -e --arg program "$SWIG_PROGRAM_ID" --arg authority "$authority" \
  '.programId == $program and .authority == $authority and
   .owner == "BPFLoaderUpgradeab1e11111111111111111111111"' \
  "$private_dir/program.json" >/dev/null; then
  echo "::error::The existing devnet program must be upgradeable by PROGRAM_AUTHORITY_KEYPAIR."
  exit 1
fi

# An explicit buffer avoids printing a recovery seed on CLI failure. Its public
# address is enough for the upgrade authority to inspect or reclaim its rent.
solana-keygen new --no-bip39-passphrase --silent --outfile "$private_dir/buffer.json" >/dev/null 2>&1
buffer=$(solana-keygen pubkey "$private_dir/buffer.json" 2>/dev/null)
mkdir deployment
printf '%s\n' "$buffer" > deployment/buffer-address.txt
cp "$private_dir/program.json" deployment/preflight.json
gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" \
  -f "ref=refs/tags/$RELEASE_TAG" -f "sha=$SOURCE_SHA" >/dev/null
gh release create "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" \
  --verify-tag --prerelease --latest=false --title "$RELEASE_TAG" \
  --notes "Devnet upgrade from $SOURCE_SHA. Deployment is pending; inspect the workflow receipts before retrying." \
  release-inputs/swig.so release-inputs/swig.so.sha256 deployment/preflight.json deployment/buffer-address.txt

echo "Deploying $SOURCE_SHA to devnet; buffer=$buffer authority=$authority"
# The authority also funds buffer rent, any required program extension and fees.
# Raw CLI errors can contain a credential-bearing RPC URL; keep them out of logs.
if ! solana program deploy release-inputs/swig.so "${solana_args[@]}" \
  --program-id "$SWIG_PROGRAM_ID" --upgrade-authority "$private_dir/authority.json" \
  --fee-payer "$private_dir/authority.json" --buffer "$private_dir/buffer.json" \
  --use-rpc --max-sign-attempts 3 --output json > "$private_dir/deploy.json" 2>/dev/null; then
  echo "::error::Deployment failed or is uncertain. Inspect devnet program $SWIG_PROGRAM_ID and buffer $buffer before retrying; authority $authority can reclaim unused buffer rent."
  exit 1
fi
jq -e --arg program "$SWIG_PROGRAM_ID" \
  '.programId == $program and (.signature | type == "string" and length > 0)' \
  "$private_dir/deploy.json" >/dev/null
# Save the transaction before subsequent RPC reads, which can fail independently.
jq '{programId, signature}' "$private_dir/deploy.json" > deployment/transaction.json
solana program show "$SWIG_PROGRAM_ID" "${solana_args[@]}" --output json \
  > deployment/program.json 2>/dev/null
jq -e --arg program "$SWIG_PROGRAM_ID" --arg authority "$authority" \
  '.programId == $program and .authority == $authority and
   .owner == "BPFLoaderUpgradeab1e11111111111111111111111"' deployment/program.json >/dev/null
solana program dump "$SWIG_PROGRAM_ID" "$private_dir/deployed.so" "${solana_args[@]}" >/dev/null 2>&1
python3 - "$private_dir/deployed.so" <<'PY'
import pathlib
import sys

expected = pathlib.Path("release-inputs/swig.so").read_bytes()
actual = pathlib.Path(sys.argv[1]).read_bytes()
# Loader-v3 may reserve more space than the ELF; only zero padding is allowed.
if not actual.startswith(expected) or any(actual[len(expected):]):
    sys.exit("Deployed program bytes do not match the release binary")
PY
binary_sha256=$(cut -d ' ' -f 1 release-inputs/swig.so.sha256)
jq --arg source_commit "$SOURCE_SHA" --arg tag "$RELEASE_TAG" \
  --arg binary_sha256 "$binary_sha256" --arg buffer "$buffer" \
  --slurpfile program deployment/program.json \
  '. + {cluster: "devnet", source_commit: $source_commit, tag: $tag,
        binary_sha256: $binary_sha256, buffer: $buffer, program: $program[0]}' \
  deployment/transaction.json > deployment/deployment-receipt.json
gh release upload "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" deployment/deployment-receipt.json
gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" \
  --notes "Deployed $SOURCE_SHA directly to devnet. The finalized on-chain binary matches swig.so; see deployment-receipt.json."
cat deployment/deployment-receipt.json >> "$GITHUB_STEP_SUMMARY"
