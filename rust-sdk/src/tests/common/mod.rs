use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use anyhow::Result;
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::{spl_token, CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    swig, AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
};
use swig_state_x::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

pub struct SwigTestContext {
    pub svm: LiteSVM,
    pub default_payer: Keypair,
}

pub fn setup_test_context() -> Result<SwigTestContext> {
    let payer = Keypair::new();
    let mut svm = LiteSVM::new();

    // Load the program
    load_program(&mut svm)?;

    // Airdrop to payer
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .map_err(|e| anyhow::anyhow!("Failed to airdrop: {:?}", e))?;

    Ok(SwigTestContext {
        svm,
        default_payer: payer,
    })
}

pub fn load_program(svm: &mut LiteSVM) -> Result<()> {
    svm.add_program_from_file(Pubkey::new_from_array(swig::ID), "../target/deploy/swig.so")
        .map_err(|_| anyhow::anyhow!("Failed to load program"))
}

pub fn create_swig_ed25519(
    context: &mut SwigTestContext,
    authority: &Keypair,
    id: [u8; 32],
) -> Result<(Pubkey, TransactionMetadata)> {
    let (swig, bump) =
        Pubkey::find_program_address(&swig_account_seeds(&id), &Pubkey::new_from_array(swig::ID));

    let create_ix = CreateInstruction::new(
        swig,
        bump,
        context.default_payer.pubkey(),
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )?;

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;
    Ok((swig, bench))
}

pub fn add_authority_with_ed25519_root(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    existing_ed25519_authority: &Keypair,
    new_authority: AuthorityConfig,
    actions: Vec<ClientAction>,
) -> Result<TransactionMetadata> {
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or_else(|| anyhow::anyhow!("Failed to get Swig account"))?;

    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig: {:?}", e))?;

    let role_id = swig
        .lookup_role_id(existing_ed25519_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Role not found"))?;

    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.default_payer.pubkey(),
        existing_ed25519_authority.pubkey(),
        role_id,
        new_authority,
        actions,
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
        &[&context.default_payer, existing_ed25519_authority],
    )
    .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;
    Ok(bench)
}

pub fn setup_mint(svm: &mut LiteSVM, payer: &Keypair) -> anyhow::Result<Pubkey> {
    let mint = CreateMint::new(svm, payer)
        .decimals(9)
        .token_program_id(&spl_token::ID)
        .send()
        .map_err(|e| anyhow::anyhow!("Failed to create mint {:?}", e))?;
    Ok(mint)
}

pub fn setup_ata(
    svm: &mut LiteSVM,
    mint: &Pubkey,
    user: &Pubkey,
    payer: &Keypair,
) -> Result<Pubkey, anyhow::Error> {
    CreateAssociatedTokenAccount::new(svm, payer, mint)
        .owner(user)
        .send()
        .map_err(|_| anyhow::anyhow!("Failed to create associated token account"))
}

pub fn mint_to(
    svm: &mut LiteSVM,
    mint: &Pubkey,
    authority: &Keypair,
    to: &Pubkey,
    amount: u64,
) -> Result<(), anyhow::Error> {
    MintTo::new(svm, authority, mint, to, amount)
        .send()
        .map_err(|e| anyhow::anyhow!("Failed to mint {:?}", e))?;
    Ok(())
}

/// Helper function to get the current signature counter for a secp256k1
/// authority
pub fn get_secp256k1_counter(
    context: &SwigTestContext,
    swig_key: &Pubkey,
    wallet_pubkey: &[u8], // The uncompressed public key bytes (64 bytes)
) -> Result<u32, String> {
    // Get the swig account data
    let swig_account = context
        .svm
        .get_account(swig_key)
        .ok_or("Swig account not found")?;

    // Use the public utility function from the SDK
    crate::utils::get_secp256k1_signature_counter(&swig_account.data, wallet_pubkey)
        .map_err(|e| format!("Failed to get signature counter: {:?}", e))
}

/// Helper function to get the current signature counter for a secp256k1
/// authority using LocalSigner
pub fn get_secp256k1_counter_from_wallet(
    context: &SwigTestContext,
    swig_key: &Pubkey,
    wallet: &PrivateKeySigner,
) -> Result<u32, String> {
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let authority_bytes = &eth_pubkey[1..]; // Remove the first byte (0x04 prefix) - this gives us 64 bytes

    get_secp256k1_counter(context, swig_key, authority_bytes)
}

pub fn create_swig_secp256k1(
    context: &mut SwigTestContext,
    wallet: &PrivateKeySigner,
    id: [u8; 32],
) -> Result<(Pubkey, TransactionMetadata)> {
    let (swig, bump) =
        Pubkey::find_program_address(&swig_account_seeds(&id), &Pubkey::new_from_array(swig::ID));

    // Get the uncompressed public key and remove the 0x04 prefix
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let authority_bytes = &eth_pubkey[1..]; // Remove the first byte (0x04 prefix)

    let create_ix = CreateInstruction::new(
        swig,
        bump,
        context.default_payer.pubkey(),
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: authority_bytes,
        },
        vec![ClientAction::All(All {})],
        id,
    )?;

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;
    Ok((swig, bench))
}
