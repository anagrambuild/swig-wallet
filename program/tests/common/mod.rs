use anyhow::Result;
use borsh::BorshDeserialize;
use litesvm::{
    types::{TransactionMetadata, TransactionResult},
    LiteSVM,
};
use litesvm_token::{spl_token, CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_program,
    transaction::{Transaction, VersionedTransaction},
};
use swig::actions::initialize_config_v1::InitializeConfigV1;
use swig_interface::{
    global_config_key, AddAuthorityInstruction, AuthorityConfig, CreateInstruction,
    InitializeConfigInstruction,
};
use swig_state::{
    authority::Ed25519SessionAuthorityDataCreate, config_seeds, swig_account_seeds, Action, Swig,
};

pub fn program_id() -> Pubkey {
    swig::ID.into()
}

pub fn add_authority_with_ed25519_root<'a>(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    existing_ed25519_authority: &Keypair,
    new_authority: AuthorityConfig,
    actions: Vec<Action>,
    start_slot: u64,
    end_slot: u64,
) -> anyhow::Result<(Swig, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = Swig::try_from_slice(&swig_account.data)?;
    let role = swig
        .lookup_role(existing_ed25519_authority.pubkey().as_ref())
        .unwrap();
    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.default_payer.pubkey(),
        existing_ed25519_authority.pubkey(),
        role.index as u8,
        new_authority,
        start_slot,
        end_slot,
        actions,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create add authority instruction {:?}", e))?;
    let msg = v0::Message::try_compile(
        &payer_pubkey,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(10000000),
            add_authority_ix,
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[
            context.default_payer.insecure_clone(),
            existing_ed25519_authority.insecure_clone(),
        ],
    )
    .unwrap();
    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = Swig::try_from_slice(&swig_account.data)?;
    Ok((swig, bench))
}

pub fn create_swig_ed25519(
    context: &mut SwigTestContext,
    authority: &Keypair,
    id: &[u8],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(id), &program_id());
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        AuthorityConfig {
            authority_type: swig_state::AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        id,
        0,
        0,
    )?;

    let msg = v0::Message::try_compile(
        &payer_pubkey,
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[context.default_payer.insecure_clone()],
    )
    .unwrap();
    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;
    Ok((swig, bench))
}

pub fn create_swig_ed25519_session(
    context: &mut SwigTestContext,
    authority: &Keypair,
    id: &[u8],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(id), &program_id());

    let authority_pubkey = authority.pubkey().to_bytes();
    let authority_data = Ed25519SessionAuthorityDataCreate::new(&authority_pubkey, &100);
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        AuthorityConfig {
            authority_type: swig_state::AuthorityType::Ed25519Session,
            authority: authority_data.into_bytes().as_ref(),
        },
        id,
        0,
        0,
    )?;

    let msg = v0::Message::try_compile(
        &payer_pubkey,
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[context.default_payer.insecure_clone()],
    )
    .unwrap();
    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;
    Ok((swig, bench))
}

pub struct SwigTestContext {
    pub svm: LiteSVM,
    pub default_payer: Keypair,
    pub swig_config: Pubkey,
}

pub fn setup_test_context() -> anyhow::Result<SwigTestContext> {
    let payer = Keypair::new();
    let mut svm = LiteSVM::new();

    load_program(&mut svm)?;
    let swig_config = Pubkey::find_program_address(&config_seeds(), &program_id()).0;
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .map_err(|e| anyhow::anyhow!("Failed to airdrop {:?}", e))?;
    let swig_create_config_ix = swig_interface::InitializeConfigInstruction::new(
        payer.pubkey(),
        payer.pubkey(),
        system_program::ID,
    );
    let swig_create_config_message = v0::Message::try_compile(
        &payer.pubkey(),
        &[swig_create_config_ix],
        &[],
        svm.latest_blockhash(),
    )?;

    let swig_create_config_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(swig_create_config_message), &[&payer])?;

    let swig_create_config_result = svm.send_transaction(swig_create_config_tx);
    println!("swig_create_config_result: {:?}", swig_create_config_result);
    Ok(SwigTestContext {
        svm,
        default_payer: payer,
        swig_config,
    })
}

pub fn load_program(svm: &mut LiteSVM) -> anyhow::Result<()> {
    svm.add_program_from_file(program_id(), "../target/deploy/swig.so")
        .map_err(|_| anyhow::anyhow!("Failed to load program"))
}

pub fn setup_mint(svm: &mut LiteSVM, payer: &Keypair) -> anyhow::Result<Pubkey> {
    let mint = CreateMint::new(svm, payer)
        .decimals(9)
        .token_program_id(&spl_token::ID)
        .send()
        .map_err(|e| anyhow::anyhow!("Failed to create mint {:?}", e))?;
    Ok(mint)
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
