use anyhow::Result;
use solana_loader_v3_interface::instruction::{
    self as bpf_loader_upgradeable, UpgradeableLoaderInstruction,
};
use solana_sdk::{
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use squads_multisig::{
    anchor_lang::{AnchorDeserialize, AnchorSerialize},
    pda::{get_proposal_pda, get_transaction_pda, get_vault_pda},
    squads_multisig_program::{
        ProposalCreateArgs, TransactionMessage, VaultTransactionCreateArgs, VaultTransactionMessage,
    },
    vault_transaction::VaultTransactionMessageExt,
};
use swig_release::{config::ReleaseConfig, proposal::build_proposal};

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
    let memo = format!(
        "Swig upgrade {}; commit={}; sha256={}",
        "t".repeat(80),
        "a".repeat(40),
        "b".repeat(64)
    );
    let proposal = build_proposal(&config, proposer.pubkey(), buffer, 42, 5, memo.clone())?;
    let vault = get_vault_pda(
        &config.multisig,
        config.vault_index,
        Some(&config.squads_program),
    )
    .0;
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
    assert_eq!(create_args.memo, Some(memo));
    let stored_message =
        TransactionMessage::deserialize(&mut create_args.transaction_message.as_slice())?;
    let stored_message = VaultTransactionMessage::try_from(stored_message)?;
    let [upgrade] = stored_message.instructions.as_slice() else {
        anyhow::bail!("Expected exactly one upgrade instruction")
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
    let expected_upgrade =
        bpf_loader_upgradeable::upgrade(&config.program, &buffer, &vault, &proposer.pubkey());
    let expected = TransactionMessage::try_compile(&vault, &[expected_upgrade], &[])?;
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
    let message =
        Message::new_with_blockhash(&proposal.instructions, Some(&proposer.pubkey()), &hash);
    let mut signed = Transaction::new_unsigned(message);
    signed.try_sign(&[&proposer], hash)?;
    signed.verify()?;
    assert!(bincode::serialize(&signed)?.len() <= 1232);
    Ok(())
}
