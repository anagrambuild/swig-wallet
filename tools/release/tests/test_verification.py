import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RELEASE = Path(__file__).resolve().parents[1]
SCRIPT = RELEASE / "verification.sh"
COMMIT = "541f225f50f922ad3d12134dc6ffd963c7c39ad5"
REPOSITORY = "https://github.com/anagrambuild/swig-wallet"
PROGRAM = "swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB"
UPLOADER = "8o2ZThbZ5Bky4RcPVBYjyWuzVtqfwfqPMbsboTkFf3aQ"
IMAGE = "solanafoundation/solana-verifiable-build@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd"
BUILD_ARGS = ["--library-name", "swig", "--base-image", IMAGE, "--arch", "v3"]


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "release"
        self.artifacts.mkdir()
        binary = b"\x7fELFtest-program\0\0"
        (self.artifacts / "swig.so").write_bytes(binary)
        self.hash = hashlib.sha256(binary.rstrip(b"\0")).hexdigest()
        self.metadata = {
            "repository": REPOSITORY,
            "commit": COMMIT,
            "cli_version": "0.5.2",
            "build_args": BUILD_ARGS,
            "executable_hash": self.hash,
        }
        self.receipt = {"source_commit": COMMIT, "program": PROGRAM, "verification_observed_deploy_slot": 123455}
        self.state = {
            "commit": COMMIT,
            "genesis": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
            "onchain_hash": self.hash,
            "program": {"authority": UPLOADER, "lastDeploySlot": 123456},
            "pda": "\n".join([
                f"Program Id: {PROGRAM}", f"Signer: {UPLOADER}",
                f"Git Url: {REPOSITORY}", f"Commit: {COMMIT}",
                "Deployed Slot: 123455", "Version: 0.5.2",
                f"Args: {json.dumps(BUILD_ARGS)}",
            ]),
            "remote_status": [{
                "signer": UPLOADER, "commit": COMMIT, "is_verified": True,
                "repo_url": f"{REPOSITORY}/tree/{COMMIT}",
                "on_chain_hash": self.hash, "executable_hash": self.hash,
            }],
        }
        commands = self.root / "bin"
        commands.mkdir()
        fixture = commands / "fixture"
        fixture.write_bytes((RELEASE / "tests/fixtures/verification_commands.py").read_bytes())
        fixture.chmod(0o755)
        for command in ("solana", "solana-verify", "curl", "git"):
            (commands / command).symlink_to(fixture)
        self.env = {
            **os.environ,
            "PATH": str(commands) + os.pathsep + os.environ["PATH"],
            "GITHUB_REPOSITORY": "anagrambuild/swig-wallet",
            "SOURCE_SHA": COMMIT, "SOLANA_RPC_URL": "https://rpc.invalid",
            "SWIG_PROGRAM_ID": PROGRAM, "CLUSTER": "mainnet",
            "VERIFICATION_FIXTURE": str(self.root / "fixture.json"),
            "VERIFICATION_CALLS": str(self.root / "calls.jsonl"),
        }

    def run_script(self, mode):
        (self.artifacts / "verification.json").write_text(json.dumps(self.metadata))
        (self.root / "fixture.json").write_text(json.dumps(self.state))
        (self.artifacts / "proposal-receipt.json").write_text(json.dumps(self.receipt))
        return subprocess.run(
            ["bash", str(SCRIPT), mode, str(self.artifacts)],
            cwd=self.root, env=self.env, text=True, capture_output=True,
        )

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def assert_no_submission(self):
        self.assertFalse(any(call[1:3] == ["remote", "submit-job"] for call in self.calls()))

    def test_build_records_recipe_and_copies_exact_binary(self):
        result = self.run_script("build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.artifacts / "verification.json").read_text()), self.metadata)
        self.assertEqual((self.artifacts / "swig.so").read_bytes(), (self.root / "target/deploy/swig.so").read_bytes())
        self.assertIn(["solana-verify", "build", *BUILD_ARGS], self.calls())

    def test_build_rejects_different_checkout(self):
        self.state["commit"] = "a" * 40
        self.assertNotEqual(self.run_script("build").returncode, 0)
        self.assertFalse(any(call[1:2] == ["build"] for call in self.calls()))

    def test_check_devnet_matches_without_export_or_submission(self):
        self.env["CLUSTER"] = "devnet"
        self.state["genesis"] = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
        result = self.run_script("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("matches devnet", result.stdout)
        self.assert_no_submission()
        self.assertFalse(any(call[1:2] == ["export-pda-tx"] for call in self.calls()))

    def test_metadata_mismatch_rejects_before_rpc(self):
        for field, wrong in (("commit", "a" * 40), ("repository", "https://github.com/wrong/repo"),
                             ("build_args", ["--arch", "v1"]), ("executable_hash", "")):
            with self.subTest(field=field):
                saved = self.metadata[field]
                self.metadata[field] = wrong
                (self.root / "calls.jsonl").write_text("")
                self.assertNotEqual(self.run_script("submit").returncode, 0)
                self.assertEqual(self.calls(), [["solana-verify", "--version"]])
                self.metadata[field] = saved

    def test_changed_binary_rejects_before_export(self):
        (self.artifacts / "swig.so").write_bytes(b"different binary")
        self.assertNotEqual(self.run_script("submit").returncode, 0)
        self.assertFalse(any(call[1:2] == ["export-pda-tx"] for call in self.calls()))

    def test_wrong_deployed_hash_rejects_before_export(self):
        self.state["onchain_hash"] = "a" * 64
        result = self.run_script("submit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Deployed program does not match", result.stderr)
        self.assertFalse(any(call[1:2] == ["export-pda-tx"] for call in self.calls()))

    def test_receipt_mismatch_or_unexecuted_upgrade_rejects(self):
        for field, wrong in (("source_commit", "a" * 40), ("program", UPLOADER),
                             ("verification_observed_deploy_slot", 123456)):
            with self.subTest(field=field):
                saved = self.receipt[field]
                self.receipt[field] = wrong
                self.assertNotEqual(self.run_script("submit").returncode, 0)
                self.assert_no_submission()
                self.receipt[field] = saved

    def test_wrong_network_rejects(self):
        self.state["genesis"] = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
        self.assertNotEqual(self.run_script("submit").returncode, 0)
        self.assert_no_submission()

    def test_devnet_remote_submission_rejects(self):
        self.env["CLUSTER"] = "devnet"
        self.state["genesis"] = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
        result = self.run_script("submit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only supports mainnet", result.stderr)
        self.assert_no_submission()

    def test_stale_pda_rejects_before_submission(self):
        original = self.state["pda"]
        for old, new in ((COMMIT, "a" * 40), ("123455", "123454"), ("v3", "v1"),
                         (UPLOADER, PROGRAM), (REPOSITORY, "https://github.com/wrong/repo")):
            with self.subTest(old=old):
                self.state["pda"] = original.replace(old, new)
                self.assertNotEqual(self.run_script("submit").returncode, 0)
                self.assert_no_submission()

    def test_success_requires_matching_remote_attestation(self):
        result = self.run_script("submit")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OtterSec verified", result.stdout)

    def test_cli_zero_exit_is_insufficient_when_attestation_differs(self):
        for field, wrong in (("is_verified", False), ("commit", "a" * 40),
                             ("signer", PROGRAM), ("on_chain_hash", "b" * 64),
                             ("executable_hash", "b" * 64), ("repo_url", REPOSITORY)):
            with self.subTest(field=field):
                saved = self.state["remote_status"][0][field]
                self.state["remote_status"][0][field] = wrong
                result = self.run_script("submit")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("OtterSec verified", result.stdout)
                self.state["remote_status"][0][field] = saved

    def test_status_endpoint_failure_is_not_success(self):
        self.state["http_failure"] = True
        result = self.run_script("submit")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("OtterSec verified", result.stdout)


if __name__ == "__main__":
    unittest.main()
