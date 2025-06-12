use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use anyhow::Result;
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::{spl_token, CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    swig, AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
    CreateSubAccountInstruction, SubAccountSignInstruction, ToggleSubAccountInstruction,
    WithdrawFromSubAccountInstruction,
};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, sub_account::SubAccount},
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        secp256r1::CreateSecp256r1SessionAuthority, AuthorityType,
    },
    swig::{sub_account_seeds, swig_account_seeds, SwigWithRoles},
    IntoBytes, Transmutable,
};
pub type Context = SwigTestContext;
pub fn program_id() -> Pubkey {
    swig::ID.into()
}

pub fn add_authority_with_ed25519_root<'a>(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    existing_ed25519_authority: &Keypair,
    new_authority: AuthorityConfig,
    actions: Vec<ClientAction>,
) -> anyhow::Result<TransactionMetadata> {
    context.svm.expire_blockhash();
    let payer_pubkey = context.default_payer.pubkey();
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(existing_ed25519_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();
    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.default_payer.pubkey(),
        existing_ed25519_authority.pubkey(),
        role_id,
        new_authority,
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
    Ok(bench)
}

pub fn create_swig_secp256k1(
    context: &mut SwigTestContext,
    wallet: &PrivateKeySigner,
    id: [u8; 32],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    // Get the Ethereum public key
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &eth_pubkey[1..],
        },
        vec![ClientAction::All(All {})],
        id,
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

pub fn create_swig_ed25519(
    context: &mut SwigTestContext,
    authority: &Keypair,
    id: [u8; 32],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        #[cfg(feature = "program_scope_test")]
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
        #[cfg(not(feature = "program_scope_test"))]
        vec![ClientAction::All(All {})],
        id,
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
    id: [u8; 32],
    session_max_length: u64,
    initial_session_key: [u8; 32],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    let authority_pubkey = authority.pubkey().to_bytes();
    let authority_data = CreateEd25519SessionAuthority::new(
        authority_pubkey,
        initial_session_key,
        session_max_length,
    );
    let authority_data_bytes = authority_data
        .into_bytes()
        .map_err(|e| anyhow::anyhow!("Failed to serialize authority data {:?}", e))?;
    let initial_authority = AuthorityConfig {
        authority_type: AuthorityType::Ed25519Session,
        authority: authority_data_bytes,
    };

    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        initial_authority,
        vec![ClientAction::All(All {})],
        id,
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

pub fn create_swig_secp256k1_session(
    context: &mut SwigTestContext,
    wallet: &PrivateKeySigner,
    id: [u8; 32],
    session_max_length: u64,
    initial_session_key: [u8; 32],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    // Get the Ethereum public key
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    // Create the session authority data
    let mut authority_data = CreateSecp256k1SessionAuthority {
        public_key: eth_pubkey[1..].try_into().unwrap(),
        session_key: initial_session_key,
        max_session_length: session_max_length,
    };

    let initial_authority = AuthorityConfig {
        authority_type: AuthorityType::Secp256k1Session,
        authority: authority_data
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize authority data {:?}", e))?,
    };

    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        initial_authority,
        vec![ClientAction::All(All {})],
        id,
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

pub fn create_swig_secp256r1_session(
    context: &mut SwigTestContext,
    public_key: &[u8; 33],
    id: [u8; 32],
    session_max_length: u64,
    initial_session_key: [u8; 32],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    use swig_state_x::authority::secp256r1::CreateSecp256r1SessionAuthority;

    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    // Create the session authority data
    let authority_data =
        CreateSecp256r1SessionAuthority::new(*public_key, initial_session_key, session_max_length);

    let initial_authority = AuthorityConfig {
        authority_type: AuthorityType::Secp256r1Session,
        authority: authority_data
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize authority data {:?}", e))?,
    };

    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        initial_authority,
        vec![ClientAction::All(All {})],
        id,
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
}

pub fn setup_test_context() -> anyhow::Result<SwigTestContext> {
    let payer = Keypair::new();
    let mut svm = LiteSVM::new();

    load_program(&mut svm)?;
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .map_err(|e| anyhow::anyhow!("Failed to airdrop {:?}", e))?;
    Ok(SwigTestContext {
        svm,
        default_payer: payer,
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

// Helper to create a sub-account
pub fn create_sub_account(
    context: &mut SwigTestContext,
    swig_account: &Pubkey,
    authority: &Keypair,
    role_id: u32,
    id: [u8; 32],
) -> anyhow::Result<Pubkey> {
    // Derive the sub-account address
    let role_id_bytes = role_id.to_le_bytes();
    let (sub_account, sub_account_bump) =
        Pubkey::find_program_address(&sub_account_seeds(&id, &role_id_bytes), &program_id());

    // Create the instruction to create a sub-account
    let create_sub_account_ix = CreateSubAccountInstruction::new_with_ed25519_authority(
        *swig_account,
        authority.pubkey(),
        authority.pubkey(),
        sub_account,
        role_id,
        sub_account_bump,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create sub-account instruction: {:?}", e))?;

    // Send the transaction
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[create_sub_account_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[authority.insecure_clone()])
            .unwrap();

    context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to create sub-account: {:?}", e))?;

    Ok(sub_account)
}

// Helper to toggle a sub-account's enabled state
pub fn toggle_sub_account(
    context: &mut SwigTestContext,
    swig_account: &Pubkey,
    sub_account: &Pubkey,
    authority: &Keypair,
    role_id: u32,
    enabled: bool,
) -> anyhow::Result<TransactionMetadata> {
    // Create the instruction to toggle a sub-account
    let toggle_ix = ToggleSubAccountInstruction::new_with_ed25519_authority(
        *swig_account,
        authority.pubkey(),
        authority.pubkey(),
        *sub_account,
        role_id,
        enabled,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create toggle sub-account instruction: {:?}", e))?;

    // Send the transaction
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[toggle_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[authority.insecure_clone()])
            .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to toggle sub-account: {:?}", e))?;

    Ok(bench)
}

// Helper to sign instructions with a sub-account
pub fn sub_account_sign(
    context: &mut SwigTestContext,
    swig_account: &Pubkey,
    sub_account: &Pubkey,
    authority: &Keypair,
    role_id: u32,
    instructions: Vec<Instruction>,
) -> anyhow::Result<TransactionMetadata> {
    // Create the instruction to sign with a sub-account
    let sub_account_sign_ix = SubAccountSignInstruction::new_with_ed25519_authority(
        *swig_account,
        *sub_account,
        authority.pubkey(),
        authority.pubkey(),
        role_id,
        instructions,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create sub-account sign instruction: {:?}", e))?;

    // Send the transaction
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[sub_account_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[authority.insecure_clone()])
            .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to sign with sub-account: {:?}", e))?;

    Ok(bench)
}

// Helper to withdraw from a sub-account
pub fn withdraw_from_sub_account(
    context: &mut SwigTestContext,
    swig_account: &Pubkey,
    sub_account: &Pubkey,
    authority: &Keypair,
    role_id: u32,
    amount: u64,
) -> anyhow::Result<TransactionMetadata> {
    // Create the instruction to withdraw from a sub-account
    let withdraw_ix = WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
        *swig_account,
        authority.pubkey(),
        authority.pubkey(),
        *sub_account,
        role_id,
        amount,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create withdraw instruction: {:?}", e))?;

    // Send the transaction
    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[withdraw_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[authority.insecure_clone()])
            .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to withdraw from sub-account: {:?}", e))?;

    Ok(bench)
}

pub fn withdraw_token_from_sub_account(
    context: &mut SwigTestContext,
    swig_account: &Pubkey,
    sub_account: &Pubkey,
    authority: &Keypair,
    sub_account_ata: &Pubkey,
    swig_ata: &Pubkey,
    token_program: &Pubkey,
    role_id: u32,
    amount: u64,
) -> anyhow::Result<TransactionMetadata> {
    let withdraw_ix = WithdrawFromSubAccountInstruction::new_token_with_ed25519_authority(
        *swig_account,
        authority.pubkey(),
        context.default_payer.pubkey(),
        *sub_account,
        *sub_account_ata,
        *swig_ata,
        *token_program,
        role_id,
        amount,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create withdraw instruction: {:?}", e))?;

    let message = v0::Message::try_compile(
        &authority.pubkey(),
        &[withdraw_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            authority.insecure_clone(),
            context.default_payer.insecure_clone(),
        ],
    )
    .unwrap();
    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to withdraw from sub-account: {:?}", e))?;
    println!("bench: {:?}", bench);
    Ok(bench)
}

pub fn add_sub_account_permission(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    authority: &Keypair,
) -> anyhow::Result<TransactionMetadata> {
    // First get the role_id
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;

    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    let role_id = swig
        .lookup_role_id(authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    // Add the SubAccount permission to the existing authority
    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.default_payer.pubkey(),
        authority.pubkey(),
        role_id,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount {
            sub_account: [0; 32],
        })],
    )
    .map_err(|e| anyhow::anyhow!("Failed to create add authority instruction: {:?}", e))?;

    // Send the transaction
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(10000000),
            add_authority_ix,
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            context.default_payer.insecure_clone(),
            authority.insecure_clone(),
        ],
    )
    .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to add SubAccount permission: {:?}", e))?;

    Ok(bench)
}
