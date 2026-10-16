import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy-devnet.sh"
PROGRAM = "swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB"
AUTHORITY = "test-authority"
SECRET = "test-private-key-material"
STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
mode = os.environ.get("TEST_MODE", "success")
with open("calls.jsonl", "a") as calls:
    calls.write(json.dumps([tool, *args]) + "\n")

def option(name):
    return args[args.index(name) + 1]

if tool == "solana-keygen":
    if args[0] == "pubkey":
        key = Path(args[1])
        assert key.stat().st_mode & 0o777 == 0o600
        if key.name == "authority.json":
            assert "PROGRAM_AUTHORITY_KEYPAIR" not in os.environ
            assert key.read_text() == "test-private-key-material"
            if mode == "invalid-keypair":
                sys.exit(1)
            print("test-authority")
        else:
            print("test-buffer")
    else:
        assert args[0] == "new" and "--silent" in args
        Path(option("--outfile")).write_text("test-buffer-key-material")
elif tool == "gh":
    if args[:2] == ["release", "upload"] and mode == "publish-failure":
        sys.exit(1)
elif tool == "solana":
    assert option("--url") == "https://devnet.invalid/secret-rpc-token"
    assert option("--commitment") == "finalized"
    assert Path(option("--keypair")).exists()
    if args[0] == "genesis-hash":
        print("wrong-cluster" if mode == "wrong-cluster" else
              "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG")
    elif args[:2] == ["program", "show"]:
        after_deploy = Path("deployed").exists()
        if mode == "missing-program" or (after_deploy and mode == "post-read-failure"):
            sys.exit(1)
        print(json.dumps({
            "programId": os.environ["SWIG_PROGRAM_ID"],
            "owner": "wrong-owner" if mode == "wrong-owner" else
                     "BPFLoaderUpgradeab1e11111111111111111111111",
            "authority": "wrong-authority" if mode == "wrong-authority" or
                         (after_deploy and mode == "changed-authority") else "test-authority",
            "programdataAddress": "test-program-data", "lastDeploySlot": 42,
            "dataLen": 100, "lamports": 1000000,
        }))
    elif args[:2] == ["program", "deploy"]:
        assert option("--program-id") == os.environ["SWIG_PROGRAM_ID"]
        assert option("--upgrade-authority") == option("--fee-payer") == option("--keypair")
        assert Path(option("--buffer")).exists()
        assert "--use-rpc" in args and "--final" not in args
        assert option("--output") == "json"
        assert Path(args[2]).read_bytes() == b"\x7fELFtest-binary"
        if mode == "deploy-failure":
            print("secret-rpc-token test-private-key-material")
            print("secret-rpc-token test-private-key-material", file=sys.stderr)
            sys.exit(1)
        Path("deployed").touch()
        print(json.dumps({
            "programId": "wrong-program" if mode == "wrong-receipt" else os.environ["SWIG_PROGRAM_ID"],
            "signature": None if mode == "missing-signature" else "test-signature",
        }))
    elif args[:2] == ["program", "dump"]:
        data = Path("release-inputs/swig.so").read_bytes()
        if mode == "wrong-binary":
            data = b"bad" + data[3:]
        elif mode == "truncated-binary":
            data = data[:-1]
        elif mode == "nonzero-padding":
            data += b"\x01"
        else:
            data += b"\x00" * 32
        Path(args[3]).write_bytes(data)
    else:
        raise AssertionError(args)
else:
    raise AssertionError(tool)
'''


class DevnetDeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for tool in ("solana", "solana-keygen", "gh"):
            executable = self.bin / tool
            executable.write_text(STUB)
            executable.chmod(0o700)
        inputs = self.root / "release-inputs"
        inputs.mkdir()
        (inputs / "swig.so").write_bytes(b"\x7fELFtest-binary")
        (inputs / "swig.so.sha256").write_text("abc123  swig.so\n")
        self.runner_temp = self.root / "runner-temp"
        self.runner_temp.mkdir()
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "PROGRAM_AUTHORITY_KEYPAIR": SECRET,
            "SOLANA_RPC_URL": "https://devnet.invalid/secret-rpc-token",
            "SWIG_PROGRAM_ID": PROGRAM,
            "SOURCE_SHA": "a" * 40,
            "RELEASE_TAG": "devnet-upgrade-1-aaaaaaaaaaaa",
            "GITHUB_REPOSITORY": "test/swig-wallet",
            "RUNNER_TEMP": str(self.runner_temp),
            "GITHUB_STEP_SUMMARY": str(self.root / "summary"),
            "TEST_MODE": "success",
        }

    def run_deploy(self, mode="success"):
        self.assertIsNotNone(shutil.which("jq"), "jq is required")
        result = subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.root,
            env={**self.env, "TEST_MODE": mode}, capture_output=True, text=True,
        )
        self.assertEqual(list(self.runner_temp.iterdir()), [], "private keys must be removed")
        public = result.stdout + result.stderr
        if (self.root / "deployment").exists():
            public += "".join(p.read_text() for p in (self.root / "deployment").iterdir())
        for secret in (SECRET, "secret-rpc-token", "test-buffer-key-material"):
            self.assertNotIn(secret, public)
        return result

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_not_deployed(self):
        self.assertFalse((self.root / "deployed").exists())
        self.assertFalse(any(c[0] == "gh" for c in self.calls()), "preflight must precede GitHub writes")
        self.assertFalse(any(c[:3] == ["solana", "program", "deploy"] for c in self.calls()))

    def assert_not_published(self):
        self.assertFalse(any(c[:3] == ["gh", "release", "edit"] for c in self.calls()))
        self.assertFalse((self.root / "summary").exists())

    def test_deploys_exact_binary_and_publishes_receipt(self):
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.root / "deployment/deployment-receipt.json").read_text())
        self.assertEqual(receipt["programId"], PROGRAM)
        self.assertEqual(receipt["program"]["authority"], AUTHORITY)
        self.assertEqual(receipt["signature"], "test-signature")
        self.assertEqual(receipt["source_commit"], "a" * 40)
        self.assertEqual(receipt["cluster"], "devnet")
        self.assertEqual(receipt["buffer"], "test-buffer")
        self.assertEqual(json.loads((self.root / "summary").read_text()), receipt)
        calls = self.calls()
        create = next(i for i, c in enumerate(calls) if c[:3] == ["gh", "release", "create"])
        deploy = next(i for i, c in enumerate(calls) if c[:3] == ["solana", "program", "deploy"])
        self.assertLess(create, deploy)
        self.assertIn("--prerelease", calls[create])
        self.assertIn("--latest=false", calls[create])

    def test_rejects_missing_config(self):
        del self.env["PROGRAM_AUTHORITY_KEYPAIR"]
        result = self.run_deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PROGRAM_AUTHORITY_KEYPAIR is required", result.stderr)
        self.assert_not_deployed()

    def test_rejects_incorrect_program_id(self):
        self.env["SWIG_PROGRAM_ID"] = "wrong-program"
        self.assertNotEqual(self.run_deploy().returncode, 0)
        self.assert_not_deployed()

    def test_rejects_tag_for_different_source(self):
        self.env["RELEASE_TAG"] = "devnet-upgrade-1-bbbbbbbbbbbb"
        self.assertNotEqual(self.run_deploy().returncode, 0)
        self.assert_not_deployed()

    def test_preflight_rejections_have_no_external_writes(self):
        for mode in ("wrong-cluster", "invalid-keypair", "wrong-owner", "wrong-authority", "missing-program"):
            with self.subTest(mode=mode):
                result = self.run_deploy(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assert_not_deployed()

    def test_failed_upload_keeps_public_recovery_without_secrets(self):
        result = self.run_deploy("deploy-failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Deployment failed or is uncertain", result.stdout)
        self.assertEqual((self.root / "deployment/buffer-address.txt").read_text(), "test-buffer\n")
        self.assert_not_published()

    def test_post_deploy_rpc_failure_preserves_transaction(self):
        self.assertNotEqual(self.run_deploy("post-read-failure").returncode, 0)
        self.assertEqual(json.loads((self.root / "deployment/transaction.json").read_text())["signature"], "test-signature")
        self.assert_not_published()

    def test_publish_failure_preserves_verified_receipt(self):
        self.assertNotEqual(self.run_deploy("publish-failure").returncode, 0)
        self.assertTrue((self.root / "deployment/deployment-receipt.json").exists())
        self.assert_not_published()


def verification_failure_test(mode):
    def test(self):
        result = self.run_deploy(mode)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "deployed").exists())
        self.assertFalse((self.root / "deployment/deployment-receipt.json").exists())
        self.assert_not_published()
    return test


for mode in ("wrong-binary", "truncated-binary", "nonzero-padding", "changed-authority", "wrong-receipt", "missing-signature"):
    setattr(DevnetDeployTests, "test_rejects_" + mode.replace("-", "_"), verification_failure_test(mode))


if __name__ == "__main__":
    unittest.main()
