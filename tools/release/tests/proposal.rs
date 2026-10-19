use anyhow::Result;
use solana_loader_v3_interface::instruction::{
    self as bpf_loader_upgradeable, UpgradeableLoaderInstruction,
};
use solana_sdk::{
    hash::Hash,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use squads_multisig::{
    anchor_lang::{AnchorDeserialize, AnchorSerialize},
    pda::{get_proposal_pda, get_transaction_pda, get_vault_pda},
    squads_multisig_program::{
        ProposalCreateArgs, TransactionMessage, VaultTransactionCreateArgs, VaultTransactionMessage,
    },
    vault_transaction::VaultTransactionMessageExt,
};
use swig_release::{
    config::ReleaseConfig,
    proposal::build_proposal,
    transactions::build_v1_transaction,
    verification::{build_verification_instruction, VerificationManifest},
};

#[test]
fn proposal_atomically_hands_off_and_creates_active_upgrade_without_voting() -> Result<()> {
    let config = ReleaseConfig {
        rpc_url: "https://example.invalid".into(),
        squads_program: Pubkey::new_unique(),
        multisig: Pubkey::new_unique(),
        vault_index: 7,
        program: Pubkey::new_unique(),
    };
    let proposer = Keypair::new();
    let buffer = Pubkey::new_unique();
    let vault = get_vault_pda(
        &config.multisig,
        config.vault_index,
        Some(&config.squads_program),
    )
    .0;
    let manifest: VerificationManifest =
        serde_json::from_str(include_str!("fixtures/verification.json"))?;
    let verification = build_verification_instruction(config.program, vault, &manifest, 123, None)?;
    let proposal = build_proposal(
        &config,
        proposer.pubkey(),
        buffer,
        42,
        5,
        verification.instruction.clone(),
    )?;
    assert_eq!(
        proposal.transaction_address,
        get_transaction_pda(&config.multisig, 42, Some(&config.squads_program)).0
    );
    assert_eq!(
        proposal.proposal_address,
        get_proposal_pda(&config.multisig, 42, Some(&config.squads_program)).0
    );
    let [handoff, create_transaction, create_proposal] = proposal.instructions.as_slice() else {
        anyhow::bail!("Expected exactly three instructions")
    };
    assert_eq!(
        handoff,
        &bpf_loader_upgradeable::set_buffer_authority(&buffer, &proposer.pubkey(), &vault)
    );
    assert!(matches!(
        bincode::deserialize::<UpgradeableLoaderInstruction>(&handoff.data)?,
        UpgradeableLoaderInstruction::SetAuthority
    ));
    assert_eq!(create_transaction.program_id, config.squads_program);
    assert_eq!(create_proposal.program_id, config.squads_program);
    let create_args = VaultTransactionCreateArgs::deserialize(
        &mut create_transaction
            .data
            .get(8..)
            .ok_or_else(|| anyhow::anyhow!("Missing instruction data"))?,
    )?;
    assert_eq!(create_args.vault_index, 7);
    assert_eq!(create_args.ephemeral_signers, 0);
    assert_eq!(create_args.memo, None);
    let stored_message =
        TransactionMessage::deserialize(&mut create_args.transaction_message.as_slice())?;
    let stored_message = VaultTransactionMessage::try_from(stored_message)?;
    let [upgrade, metadata] = stored_message.instructions.as_slice() else {
        anyhow::bail!("Expected upgrade followed by verification metadata")
    };
    let [_, _, _, refund_index, _, _, authority_index] = upgrade.account_indexes.as_slice() else {
        anyhow::bail!("Expected the loader-v3 upgrade account layout")
    };
    let refund_index = usize::from(*refund_index);
    let authority_index = usize::from(*authority_index);
    assert_eq!(
        stored_message.account_keys.get(refund_index),
        Some(&proposer.pubkey())
    );
    assert!(stored_message.is_static_writable_index(refund_index));
    assert!(!stored_message.is_signer_index(refund_index));
    assert_eq!(
        stored_message.account_keys.get(authority_index),
        Some(&vault)
    );
    assert!(stored_message.is_signer_index(authority_index));
    assert_eq!(stored_message.num_signers, 1);
    assert_eq!(metadata.data, verification.instruction.data);
    assert_eq!(
        stored_message
            .account_keys
            .get(usize::from(metadata.program_id_index)),
        Some(&verification.instruction.program_id)
    );
    let expected_upgrade =
        bpf_loader_upgradeable::upgrade(&config.program, &buffer, &vault, &proposer.pubkey());
    let expected = TransactionMessage::try_compile(
        &vault,
        &[expected_upgrade, verification.instruction],
        &[],
    )?;
    assert_eq!(create_args.transaction_message, expected.try_to_vec()?);
    let proposal_args = ProposalCreateArgs::deserialize(
        &mut create_proposal
            .data
            .get(8..)
            .ok_or_else(|| anyhow::anyhow!("Missing proposal data"))?,
    )?;
    assert_eq!(proposal_args.transaction_index, 42);
    assert!(!proposal_args.draft);
    for instruction in [create_transaction, create_proposal] {
        assert!(instruction
            .accounts
            .iter()
            .filter(|meta| meta.is_signer)
            .all(|meta| meta.pubkey == proposer.pubkey()));
    }
    let hash = Hash::new_unique();
    let signed = build_v1_transaction(
        &proposer,
        &proposal.instructions,
        hash,
        solana_message_v1::v1::TransactionConfig::empty()
            .with_compute_unit_limit(200_000)
            .with_loaded_accounts_data_size_limit(4 * 1024 * 1024),
    )?;
    signed.verify_and_hash_message()?;
    let size = wincode::serialize(&signed)?.len();
    println!(
        "Combined v1 proposal transaction: {size} bytes ({} bytes spare)",
        4096 - size
    );
    assert!(matches!(
        signed.message,
        solana_message_v1::VersionedMessage::V1(_)
    ));
    assert!(
        size < 2048,
        "Combined v1 proposal should leave at least half its capacity unused"
    );
    Ok(())
}
