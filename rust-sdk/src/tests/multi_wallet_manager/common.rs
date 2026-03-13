use anyhow::Result;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{program_id, AddAuthorityInstruction, AuthorityConfig, ClientAction};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

use super::super::common::{create_swig_ed25519, SwigTestContext};
use crate::SwigInstructionBuilder;

/// Creates N wallets and adds the dapp keypair as an authority to each.
/// Returns a vector of (swig_id, role_id) tuples where role_id is the role_id
/// of the dapp keypair authority in each wallet.
pub fn create_wallets_with_dapp_authority(
    context: &mut SwigTestContext,
    dapp_keypair: &Keypair,
    num_wallets: usize,
) -> Result<Vec<([u8; 32], u32)>> {
    let mut results = Vec::new();

    for i in 0..num_wallets {
        // Generate a unique swig_id for each wallet
        let mut swig_id = [0u8; 32];
        swig_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());

        // Create a root authority for this wallet
        let root_authority = Keypair::new();

        // Create the swig wallet
        let (swig_key, _, _) = create_swig_ed25519(context, &root_authority, swig_id)?;

        // Add the dapp keypair as an authority with All permissions
        let swig_account = context
            .svm
            .get_account(&swig_key)
            .ok_or_else(|| anyhow::anyhow!("Failed to get Swig account"))?;

        let swig = SwigWithRoles::from_bytes(&swig_account.data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

        let root_role_id = swig
            .lookup_role_id(root_authority.pubkey().as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to lookup role id: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("Role not found"))?;

        let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
            swig_key,
            context.default_payer.pubkey(),
            root_authority.pubkey(),
            root_role_id,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: dapp_keypair.pubkey().as_ref(),
            },
            vec![ClientAction::All(All {})],
        )?;

        let msg = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[add_authority_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[&context.default_payer, &root_authority],
        )
        .unwrap();

        context
            .svm
            .send_transaction(tx)
            .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;

        // Get the role_id of the dapp keypair authority
        let swig_account = context
            .svm
            .get_account(&swig_key)
            .ok_or_else(|| anyhow::anyhow!("Failed to get Swig account after adding authority"))?;

        let swig = SwigWithRoles::from_bytes(&swig_account.data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

        let dapp_role_id = swig
            .lookup_role_id(dapp_keypair.pubkey().as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to lookup dapp role id: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("Dapp role not found"))?;

        // Fund the wallet address PDA
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_wallet_address_seeds(swig_key.as_ref()),
            &program_id(),
        );

        context
            .svm
            .airdrop(&swig_wallet_address, 1_000_000_000)
            .map_err(|e| anyhow::anyhow!("Failed to fund wallet address: {:?}", e))?;

        results.push((swig_id, dapp_role_id));
    }

    Ok(results)
}
