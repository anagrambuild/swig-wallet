use anyhow::{Context, Result};
use solana_message_v1::{v1::TransactionConfig, VersionedMessage};
use solana_sdk::{
    hash::Hash,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_transaction_v1::versioned::VersionedTransaction;
use swig_release::transactions::{build_v1_transaction, measured_limits};

#[test]
fn v1_native_codec_roundtrips_signatures_and_exceeds_the_old_limit() -> Result<()> {
    let payer = Keypair::new();
    let instruction = Instruction {
        program_id: Pubkey::new_unique(),
        accounts: vec![],
        data: vec![7; 1500],
    };
    let config = measured_limits(50_000, 300_000)?;
    let tx = build_v1_transaction(
        &payer,
        std::slice::from_ref(&instruction),
        Hash::new_unique(),
        config,
    )?;
    let bytes = wincode::serialize(&tx)?;
    assert_eq!(bytes.first(), Some(&0x81));
    assert!(bytes.len() > 1232 && bytes.len() < 4096);
    let mut decoded: VersionedTransaction = wincode::deserialize(&bytes)?;
    assert_eq!(decoded, tx);
    decoded.verify_and_hash_message()?;
    let VersionedMessage::V1(message) = &mut decoded.message else {
        anyhow::bail!("Expected v1")
    };
    assert_eq!(
        message
            .instructions
            .first()
            .context("Missing instruction")?
            .data,
        instruction.data
    );
    assert_eq!(
        message
            .account_keys
            .first()
            .context("Missing payer")?
            .to_bytes(),
        payer.pubkey().to_bytes()
    );
    message
        .instructions
        .first_mut()
        .context("Missing instruction")?
        .data
        .push(1);
    assert!(decoded.verify_and_hash_message().is_err());
    let mut oversized = instruction;
    oversized.data = vec![0; 4096];
    assert!(build_v1_transaction(&payer, &[oversized], Hash::new_unique(), config).is_err());
    assert!(
        build_v1_transaction(&payer, &[], Hash::new_unique(), TransactionConfig::empty()).is_err()
    );
    let extra_signer =
        solana_system_interface::instruction::transfer(&Pubkey::new_unique(), &payer.pubkey(), 1);
    assert!(build_v1_transaction(&payer, &[extra_signer], Hash::new_unique(), config).is_err());
    Ok(())
}

#[test]
fn v1_resource_limits_are_explicit_bounded_and_include_headroom() -> Result<()> {
    let limits = measured_limits(50_000, 32_768)?;
    assert_eq!(limits.compute_unit_limit, Some(61_000));
    assert_eq!(limits.loaded_accounts_data_size_limit, Some(65_536));
    let limits = measured_limits(1_400_000, 64 * 1024 * 1024)?;
    assert_eq!(limits.compute_unit_limit, Some(1_400_000));
    assert_eq!(
        limits.loaded_accounts_data_size_limit,
        Some(64 * 1024 * 1024)
    );
    for (units, loaded) in [(0, 1), (1, 0), (u64::MAX, 1), (1, u32::MAX)] {
        assert!(measured_limits(units, loaded).is_err());
    }
    Ok(())
}
