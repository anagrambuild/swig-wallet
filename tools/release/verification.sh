#!/usr/bin/env bash
set -euo pipefail
# Validate hashes consistently across Linux and macOS locales.
export LC_ALL=C

# This image contains cargo-build-sbf 4.3.0 and platform-tools v1.57.
build_image=solanafoundation/solana-verifiable-build@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd
verify_version=0.5.2
mode=${1:?Usage: verification.sh build|check|submit DIRECTORY}
directory=${2:?Release artifact directory is required}
repository="https://github.com/${GITHUB_REPOSITORY:?Repository is required}"
source_sha=${SOURCE_SHA:?Full release commit is required}
test "${#source_sha}" = 40
printf '%s\n' "$source_sha" | grep -Eq '^[0-9a-f]{40}$'
test "$(solana-verify --version)" = "solana-verify $verify_version"

if [ "$mode" = build ]; then
  test "$(git rev-parse HEAD)" = "$source_sha"
  solana-verify build --library-name swig --base-image "$build_image" --arch v3
  mkdir -p "$directory"
  cp target/deploy/swig.so "$directory/swig.so"
  executable_hash=$(solana-verify get-executable-hash "$directory/swig.so")
  test "${#executable_hash}" = 64
  printf '%s\n' "$executable_hash" | grep -Eq '^[0-9a-f]{64}$'
  jq -n --arg repository "$repository" --arg commit "$source_sha" \
    --arg version "$verify_version" --arg image "$build_image" --arg hash "$executable_hash" \
    '{repository: $repository, commit: $commit, cli_version: $version,
      build_args: ["--library-name", "swig", "--base-image", $image, "--arch", "v3"],
      executable_hash: $hash}' > "$directory/verification.json"
  exit 0
fi

case "$mode" in
  check|submit) ;;
  *) echo 'Expected build, check, or submit' >&2; exit 1 ;;
esac

# A release tag and its metadata must identify the same public source. Never
# accept an arbitrary command line from a downloaded artifact.
jq -e --arg repository "$repository" --arg commit "$source_sha" \
  --arg version "$verify_version" --arg image "$build_image" '
  .repository == $repository and .commit == $commit and .cli_version == $version and
  .build_args == ["--library-name", "swig", "--base-image", $image, "--arch", "v3"] and
  (.executable_hash | test("^[0-9a-f]{64}$"))
  ' "$directory/verification.json" > /dev/null

: "${SOLANA_RPC_URL:?RPC URL is required}" "${SWIG_PROGRAM_ID:?Program ID is required}"
case "${CLUSTER:?Cluster is required}" in
  mainnet) genesis=5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d ;;
  devnet) genesis=EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG ;;
  *) echo 'Expected mainnet or devnet' >&2; exit 1 ;;
esac
test "$(solana genesis-hash --url "$SOLANA_RPC_URL")" = "$genesis"
if [ "$mode" = submit ] && [ "$CLUSTER" != mainnet ]; then
  echo 'OtterSec remote verification only supports mainnet' >&2
  exit 1
fi

expected_hash=$(jq -er .executable_hash "$directory/verification.json")
test "$(solana-verify get-executable-hash "$directory/swig.so")" = "$expected_hash"
onchain_hash=$(solana-verify get-program-hash --url "$SOLANA_RPC_URL" "$SWIG_PROGRAM_ID")
if [ "$onchain_hash" != "$expected_hash" ]; then
  echo "Deployed program does not match this release: expected $expected_hash, found $onchain_hash" >&2
  exit 1
fi
echo "Release $source_sha matches $CLUSTER: $expected_hash"
[ "$mode" != check ] || exit 0

solana program show --url "$SOLANA_RPC_URL" "$SWIG_PROGRAM_ID" --output json > "$directory/program.json"
uploader=$(jq -er '.authority | select(test("^[1-9A-HJ-NP-Za-km-z]{32,44}$"))' "$directory/program.json")
slot=$(jq -er '.lastDeploySlot | select(type == "number" and . > 0)' "$directory/program.json")

# Metadata was approved alongside the upgrade. The CLI-compatible slot records
# the deployment observed while preparing that proposal, not its future execution.
# Bind it to the confirmed proposal receipt; hashes below prove the live release.
observed_slot=$(jq -er --arg commit "$source_sha" --arg program "$SWIG_PROGRAM_ID" '
  select(.source_commit == $commit and .program == $program) |
  .verification_observed_deploy_slot | select(type == "number" and . > 0)
  ' "$directory/proposal-receipt.json")
test "$slot" -gt "$observed_slot"

# The CLI has no JSON output for this command. Its version is pinned above;
# validate every build parameter before requesting a remote job.
solana-verify get-program-pda --url "$SOLANA_RPC_URL" --program-id "$SWIG_PROGRAM_ID" \
  --signer "$uploader" > "$directory/verification-pda.txt"
grep -Fxq "Program Id: $SWIG_PROGRAM_ID" "$directory/verification-pda.txt"
grep -Fxq "Signer: $uploader" "$directory/verification-pda.txt"
grep -Fxq "Git Url: $repository" "$directory/verification-pda.txt"
grep -Fxq "Commit: $source_sha" "$directory/verification-pda.txt"
grep -Fxq "Deployed Slot: $observed_slot" "$directory/verification-pda.txt"
grep -Fxq "Version: $verify_version" "$directory/verification-pda.txt"
sed -n 's/^Args: //p' "$directory/verification-pda.txt" | \
  jq -es --slurpfile metadata "$directory/verification.json" \
    'length == 1 and .[0] == $metadata[0].build_args' > /dev/null

solana-verify remote submit-job --url "$SOLANA_RPC_URL" \
  --program-id "$SWIG_PROGRAM_ID" --uploader "$uploader" | tee "$directory/remote-job.log"

# CLI 0.5.2 also exits zero for failed jobs and HTTP 409. Only a matching
# authority/commit/hash attestation counts as success.
curl --fail --silent --show-error --location --max-time 60 \
  "https://verify.osec.io/status-all/$SWIG_PROGRAM_ID" > "$directory/remote-status.json"
jq -e --arg signer "$uploader" --arg commit "$source_sha" \
  --arg repository "$repository" --arg hash "$expected_hash" '
  any(.[]; .signer == $signer and .commit == $commit and .is_verified == true and
    .repo_url == ($repository + "/tree/" + $commit) and
    .executable_hash == $hash and .on_chain_hash == $hash)
  ' "$directory/remote-status.json" > /dev/null
test "$(solana-verify get-program-hash --url "$SOLANA_RPC_URL" "$SWIG_PROGRAM_ID")" = "$expected_hash"
echo "OtterSec verified $source_sha: $expected_hash"
