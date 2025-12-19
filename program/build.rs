//! Shank IDL build script.

use std::{env, fs, path::Path};

use anyhow::anyhow;
use shank_idl::{extract_idl, manifest::Manifest, ParseIdlOpts};

fn main() {
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-env-changed=GENERATE_IDL");

    if let Err(e) = generate_idl() {
        println!("cargo:warning=Failed to generate IDL: {}", e)
    }
}

fn generate_idl() -> Result<(), Box<dyn std::error::Error>> {
    // resolve info about lib for which we generate idl
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_root = Path::new(&manifest_dir);

    let cargo_toml = crate_root.join("Cargo.toml");
    let manifest = Manifest::from_path(&cargo_toml)?;
    let lib_rel_path = manifest
        .lib_rel_path()
        .ok_or(anyhow!("program needs to be a lib"))?;

    let lib_full_path_str = crate_root.join(lib_rel_path);
    let lib_full_path = lib_full_path_str.to_str().ok_or(anyhow!("invalid path"))?;

    // extract idl and convert to json
    let opts = ParseIdlOpts {
        require_program_address: false,
        ..ParseIdlOpts::default()
    };
    let idl = extract_idl(lib_full_path, opts)?.ok_or(anyhow!("no idl could be extracted"))?;
    let idl_json = idl.try_into_json()?;

    // write to json file
    let out_dir = crate_root;
    let out_filename = format!("idl.json");
    let idl_json_path = out_dir.join(out_filename);
    fs::write(&idl_json_path, idl_json)?;

    println!("cargo:warning=IDL written to: {}", idl_json_path.display());

    Ok(())
}
