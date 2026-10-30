#!/usr/bin/env python3
"""Build protocol crate archives and check the shared program/interface types."""

import argparse
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--local-dependencies", action="store_true")
args = parser.parse_args()
repository = Path(__file__).resolve().parents[1]
crates = {
    "swig-no-padding": "no-padding",
    "swig-assertions": "assertions",
    "swig-compact-instructions": "instructions",
    "swig-state": "state",
    "swig": "program",
    "swig-interface": "interface",
}

with tempfile.TemporaryDirectory(prefix="swig-crate-packages-") as directory:
    root = Path(directory)
    source = root / "source"
    shutil.copytree(repository, source, ignore=shutil.ignore_patterns(".git", "target", ".surfpool"))
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(repository / "target")
    overrides = []
    if args.local_dependencies:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=source, env=env, text=True,
        ))
        for name, folder in crates.items():
            overrides.extend(["--config", f'patch.crates-io.{name}.path="{source / folder}"'])
        for name in ["swig-shank-render", "swig-shank-macro"]:
            candidates = [package for package in metadata["packages"] if package["name"] == name]
            if len(candidates) != 1:
                raise RuntimeError(f"Expected one pinned {name} candidate")
            path = Path(candidates[0]["manifest_path"]).parent
            overrides.extend(["--config", f'patch.crates-io.{name}.path="{path}"'])

    version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    for name in crates:
        subprocess.run(["cargo", "package", "-p", name, *overrides], cwd=source, env=env, check=True)
        archive = repository / "target/package" / f"{name}-{version}.crate"
        with tarfile.open(archive) as tar:
            prefix = f"{name}-{version}/"
            manifest = tomllib.loads(tar.extractfile(prefix + "Cargo.toml").read().decode())
            sections = [manifest, *manifest.get("target", {}).values()]
            for section in sections:
                for kind in ["dependencies", "build-dependencies"]:
                    for dependency in section.get(kind, {}).values():
                        assert "git" not in dependency and "path" not in dependency
            if name in ["swig", "swig-interface"]:
                assert prefix + "LICENSE.txt" in tar.getnames()
            if name == "swig-interface":
                assert manifest["dependencies"]["swig"]["version"] == "=" + version
            tar.extractall(root / "archives", filter="data")

    # Resolve downstream dependencies from the normalized archives, so the
    # consumer cannot accidentally rely on workspace-only manifest settings.
    for name, folder in crates.items():
        overrides = [value.replace(str(source / folder), str(root / "archives" / f"{name}-{version}")) for value in overrides]

    consumer = root / "consumer"
    (consumer / "src").mkdir(parents=True)
    (consumer / "Cargo.toml").write_text(
        '[package]\nname = "swig-interface-consumer"\nversion = "0.0.0"\nedition = "2021"\n'
        '[dependencies]\n'
        f'swig-interface = {{ path = "{root / "archives" / ("swig-interface-" + version)}" }}\n'
        f'swig = {{ version = "={version}", features = ["no-entrypoint"] }}\n'
    )
    (consumer / "src/main.rs").write_text(
        'fn main() {\n'
        '    let _: [u8; 32] = swig_interface::swig::ID;\n'
        '    let _same_type: fn(swig::actions::sign_v2::SignV2Args) =\n'
        '        |_: swig_interface::swig::actions::sign_v2::SignV2Args| {};\n'
        '}\n'
    )
    subprocess.run(["cargo", "check", *overrides], cwd=consumer, env=env, check=True)
    print("Protocol archives and canonical program type consumer passed against " + (
        "local candidates (not a registry release check)." if args.local_dependencies
        else "released crates.io dependencies."
    ))
