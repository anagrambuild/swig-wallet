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
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, sub_account::SubAccount},
    authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
        secp256r1::CreateSecp256r1SessionAuthority, AuthorityType,
    },
    swig::{sub_account_seeds, swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
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
    create_swig_secp256k1_with_key_type(context, wallet, id, false)
}

pub fn create_swig_secp256k1_with_key_type(
    context: &mut SwigTestContext,
    wallet: &PrivateKeySigner,
    id: [u8; 32],
    use_compressed: bool,
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    let authority_bytes = if use_compressed {
        // Get compressed key (33 bytes) directly
        wallet
            .credential()
            .verifying_key()
            .to_encoded_point(true)
            .to_bytes()
            .to_vec()
    } else {
        // Get uncompressed key (64 bytes) - skip the first byte (format indicator)
        let eth_pubkey = wallet
            .credential()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();
        eth_pubkey[1..].to_vec()
    };

    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        swig_wallet_address,
        wallet_address_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &authority_bytes,
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
    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        swig_wallet_address,
        wallet_address_bump,
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

    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        swig_wallet_address,
        wallet_address_bump,
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

    let compressed = true;

    // Get the Ethereum public key
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(compressed)
        .to_bytes();

    let compressed_offset = if compressed { 0 } else { 1 };

    let mut pubkey: [u8; 64] = [0; 64];
    pubkey[..eth_pubkey.len() - compressed_offset]
        .copy_from_slice(eth_pubkey[compressed_offset..].try_into().unwrap());

    // Create the session authority data
    let mut authority_data = CreateSecp256k1SessionAuthority {
        public_key: pubkey,
        session_key: initial_session_key,
        max_session_length: session_max_length,
    };

    let initial_authority = AuthorityConfig {
        authority_type: AuthorityType::Secp256k1Session,
        authority: authority_data
            .into_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize authority data {:?}", e))?,
    };

    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        swig_wallet_address,
        wallet_address_bump,
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
    use swig_state::authority::secp256r1::CreateSecp256r1SessionAuthority;

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

    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let create_ix = CreateInstruction::new(
        swig,
        bump,
        payer_pubkey,
        swig_wallet_address,
        wallet_address_bump,
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

pub fn create_swig_secp256r1(
    context: &mut SwigTestContext,
    public_key: &[u8; 33],
    id: [u8; 32],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig_address, swig_bump) =
        Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    let (swig_wallet_address, wallet_address_bump) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_address.as_ref()),
        &program_id(),
    );

    let create_ix = CreateInstruction::new(
        swig_address,
        swig_bump,
        payer_pubkey,
        swig_wallet_address,
        wallet_address_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: public_key,
        },
        vec![ClientAction::All(All {})],
        id,
    )?;

    let message = v0::Message::try_compile(
        &payer_pubkey,
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])?;

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;

    Ok((swig_address, bench))
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
    // Derive the sub-account address (keeping PDA for deterministic addressing)
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
    auth_role_id: u32,
    enabled: bool,
) -> anyhow::Result<TransactionMetadata> {
    // Create the instruction to toggle a sub-account
    let toggle_ix = ToggleSubAccountInstruction::new_with_ed25519_authority(
        *swig_account,
        authority.pubkey(),
        authority.pubkey(),
        *sub_account,
        role_id,
        auth_role_id,
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
    // Derive the swig wallet address
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_account.as_ref()),
        &program_id(),
    );
    println!(
        "withdraw_from_sub_account swig_wallet_address: {:?}",
        swig_wallet_address.to_bytes()
    );

    // Create the instruction to withdraw from a sub-account
    let withdraw_ix = WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
        *swig_account,
        authority.pubkey(),
        authority.pubkey(),
        *sub_account,
        swig_wallet_address,
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

    let bench = context.svm.send_transaction(tx).map_err(|e| {
        anyhow::anyhow!(
            "Failed to withdraw from sub-account: {}",
            e.meta.pretty_logs()
        )
    })?;

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
    // Derive the swig wallet address
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig_account.as_ref()),
        &program_id(),
    );
    let withdraw_ix = WithdrawFromSubAccountInstruction::new_token_with_ed25519_authority(
        *swig_account,
        authority.pubkey(),
        context.default_payer.pubkey(),
        *sub_account,
        swig_wallet_address,
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
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .map_err(|e| anyhow::anyhow!("Failed to create add authority instruction {:?}", e))?;

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

#[test_log::test]
fn test_compressed_key_generation() {
    use alloy_primitives::B256;
    use alloy_signer_local::LocalSigner;

    let wallet = LocalSigner::random();

    // Test compressed key generation
    let compressed_key = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(true)
        .to_bytes();

    // Test uncompressed key generation
    let uncompressed_key = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    println!("Compressed key length: {} bytes", compressed_key.len());
    println!("Uncompressed key length: {} bytes", uncompressed_key.len());

    // Verify compressed key is 33 bytes
    assert_eq!(
        compressed_key.len(),
        33,
        "Compressed key should be 33 bytes"
    );

    // Verify uncompressed key is 65 bytes
    assert_eq!(
        uncompressed_key.len(),
        65,
        "Uncompressed key should be 65 bytes"
    );

    // Verify the compressed key starts with 0x02 or 0x03
    assert!(
        compressed_key[0] == 0x02 || compressed_key[0] == 0x03,
        "Compressed key should start with 0x02 or 0x03"
    );

    // Verify the uncompressed key starts with 0x04
    assert_eq!(
        uncompressed_key[0], 0x04,
        "Uncompressed key should start with 0x04"
    );

    println!("✓ Compressed key generation test passed");
}
