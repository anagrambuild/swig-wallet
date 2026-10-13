use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use swig_release::release::{validate_preflight, CheckReceipt};

#[test]
fn preflight_binds_binary_deployment_signer_and_index() -> Result<()> {
    let saved = CheckReceipt {
        program: Pubkey::new_unique(),
        squads_program: Pubkey::new_unique(),
        multisig: Pubkey::new_unique(),
        vault_index: 3,
        proposer: Pubkey::new_unique(),
        binary_bytes: 400,
        binary_sha256: "a".repeat(64),
        program_capacity_bytes: 800,
        additional_bytes_required: 0,
        transaction_index: 7,
        buffer_rent_lamports: 100,
        proposal_rent_lamports: 100,
        upload_fee_reserve_lamports: 100,
        minimum_proposer_balance_lamports: 300,
    };
    let json = serde_json::to_vec(&saved)?;
    let current: CheckReceipt = serde_json::from_slice(&json)?;
    validate_preflight(&saved, &current)?;
    for field in [
        "program", "squads", "multisig", "vault", "proposer", "bytes", "hash", "index",
    ] {
        let mut changed: CheckReceipt = serde_json::from_slice(&json)?;
        let expected = match field {
            "program" => {
                changed.program = Pubkey::new_unique();
                "deployment or proposer"
            },
            "squads" => {
                changed.squads_program = Pubkey::new_unique();
                "deployment or proposer"
            },
            "multisig" => {
                changed.multisig = Pubkey::new_unique();
                "deployment or proposer"
            },
            "vault" => {
                changed.vault_index += 1;
                "deployment or proposer"
            },
            "proposer" => {
                changed.proposer = Pubkey::new_unique();
                "deployment or proposer"
            },
            "bytes" => {
                changed.binary_bytes += 1;
                "binary does not match"
            },
            "hash" => {
                changed.binary_sha256 = "b".repeat(64);
                "binary does not match"
            },
            "index" => {
                changed.transaction_index += 1;
                "transaction index is stale"
            },
            _ => anyhow::bail!("Unknown case"),
        };
        let error = validate_preflight(&saved, &changed).err();
        assert!(
            error.is_some_and(|e| e.to_string().contains(expected)),
            "Failed case: {field}"
        );
    }
    Ok(())
}
