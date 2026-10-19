use anyhow::Result;
use serde_json::json;
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
        verification_instruction_sha256: "c".repeat(64),
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
    validate_preflight(&saved, &saved)?;
    let json = serde_json::to_value(&saved)?;
    for (field, value) in [
        ("program", json!(Pubkey::new_unique())),
        ("squads_program", json!(Pubkey::new_unique())),
        ("multisig", json!(Pubkey::new_unique())),
        ("vault_index", json!(4)),
        ("proposer", json!(Pubkey::new_unique())),
        ("verification_instruction_sha256", json!("d".repeat(64))),
        ("binary_bytes", json!(401)),
        ("binary_sha256", json!("b".repeat(64))),
        ("transaction_index", json!(8)),
    ] {
        let mut changed = json.clone();
        changed[field] = value;
        let changed: CheckReceipt = serde_json::from_value(changed)?;
        assert!(
            validate_preflight(&saved, &changed).is_err(),
            "Accepted changed {field}"
        );
    }
    Ok(())
}
