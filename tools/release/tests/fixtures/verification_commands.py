#!/usr/bin/env python3
"""Process-boundary fixtures for the release verification script."""

import hashlib
import json
import os
from pathlib import Path
import sys

state = json.loads(Path(os.environ["VERIFICATION_FIXTURE"]).read_text())
command = Path(sys.argv[0]).name
args = sys.argv[1:]
with Path(os.environ["VERIFICATION_CALLS"]).open("a") as calls:
    calls.write(json.dumps([command, *args]) + "\n")

if command == "solana":
    if args[0] == "genesis-hash":
        print(state["genesis"])
    elif args[:2] == ["program", "show"]:
        print(json.dumps(state["program"]))
    else:
        sys.exit(f"Unexpected solana arguments: {args}")
elif command == "solana-verify":
    if args == ["--version"]:
        print("solana-verify 0.5.2")
    elif args[0] == "get-executable-hash":
        print(hashlib.sha256(Path(args[1]).read_bytes().rstrip(b"\0")).hexdigest())
    elif args[0] == "get-program-hash":
        print(state["onchain_hash"])
    elif args[0] == "get-program-pda":
        print(state["pda"])
    elif args[:2] == ["remote", "submit-job"]:
        # This is real CLI behavior: both a failed job and a conflict may exit 0.
        print("Job completed; inspect status")
    elif args[0] == "build":
        path = Path("target/deploy/swig.so")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELFtest-program\0\0")
    else:
        sys.exit(f"Unexpected solana-verify arguments: {args}")
elif command == "curl":
    if state.get("http_failure"):
        sys.exit(22)
    print(json.dumps(state["remote_status"]))
elif command == "git" and args == ["rev-parse", "HEAD"]:
    print(state["commit"])
else:
    sys.exit(f"Unexpected command: {command} {args}")
