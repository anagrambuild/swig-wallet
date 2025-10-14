use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use anyhow::{Ok, Result};
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::{spl_token, CreateAssociatedTokenAccount, CreateMint, MintTo};
use oracle_mapping_state::{
    error::MappingProgramError, scope_mapping_registry, DataLen, MintMapping, ScopeMappingRegistry,
};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    message::{v0, VersionedMessage},
    program_pack::Pack,
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
    action::{
        all::All, manage_authority::ManageAuthority, oracle_limits::OracleTokenLimit,
        oracle_recurring_limit::OracleRecurringLimit, program_scope::ProgramScope,
        sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount,
    },
    authority::{
        ed25519::{CreateEd25519SessionAuthority, ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{
            CreateSecp256k1SessionAuthority, Secp256k1Authority, Secp256k1SessionAuthority,
        },
        secp256r1::{
            CreateSecp256r1SessionAuthority, Secp256r1Authority, Secp256r1SessionAuthority,
        },
        AuthorityType,
    },
    role::Role,
    swig::{sub_account_seeds, swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    IntoBytes, Transmutable,
};
pub type Context = SwigTestContext;
pub fn program_id() -> Pubkey {
    swig::ID.into()
}

pub fn convert_swig_to_v1(context: &mut SwigTestContext, swig_pubkey: &Pubkey) {
    use swig_state::swig::Swig;

    let mut account = context
        .svm
        .get_account(swig_pubkey)
        .expect("Swig account should exist");

    if account.data.len() >= Swig::LEN {
        let last_8_start = Swig::LEN - 8;
        let reserved_lamports: u64 = 256;
        account.data[last_8_start..Swig::LEN].copy_from_slice(&reserved_lamports.to_le_bytes());
    }

    context
        .svm
        .set_account(swig_pubkey.clone(), account)
        .expect("Failed to update account");
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

pub fn load_sample_pyth_accounts(svm: &mut LiteSVM) -> anyhow::Result<()> {
    use base64;
    use solana_program::pubkey::Pubkey;
    use solana_sdk::account::Account;
    use std::str::FromStr;

    let pubkey = Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE").unwrap();
    let owner = Pubkey::from_str("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ").unwrap();

    let mut data = Account {
        lamports: 1825020,
        data: base64::decode("IvEjY51+9M1gMUcENA3t3zcf1CRyFI8kjp0abRpesqw6zYt/1dayQwHvDYtv2izrpB2hXUCV0do5Kg0vjtDGx7wPTPrIwoC1bbLod+YDAAAA6QJ4AAAAAAD4////lZpJaAAAAACVmkloAAAAAMC2EeIDAAAALL2AAAAAAADcSaEUAAAAAAA=").unwrap(),
        owner,
        executable: false,
        rent_epoch: 18446744073709551615,
    };

    svm.set_account(pubkey, data);

    Ok(())
}

pub fn load_sample_scope_data(svm: &mut LiteSVM, payer: &Keypair) -> anyhow::Result<(Pubkey)> {
    use base64;
    use solana_program::pubkey::Pubkey;
    use solana_sdk::account::Account;
    use std::str::FromStr;

    let pubkey = Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C").unwrap();
    let owner = Pubkey::from_str("HFn8GnPADiny6XqUoWE8uRPPxb29ikn4yTuPa9MF2fWJ").unwrap();

    use solana_client::rpc_client::RpcClient;

    let client = RpcClient::new("https://api.mainnet-beta.solana.com".to_string());
    let mut scope_account = client.get_account(&pubkey).unwrap();

    let mut data = Account {
        lamports: 200_700_000,
        data: scope_account.data,
        owner,
        executable: false,
        rent_epoch: 18446744073709551615,
    };

    svm.set_account(pubkey, data).unwrap();

    let mapping_pubkey = Pubkey::from_str("FbeuRDWwLvZWEU3HNtaLoYKagw9rH1NvmjpRMpjMwhDw").unwrap();
    let owner_pubkey = Pubkey::from_str("9WM51wrB9xpRzFgYJHocYNnx4DF6G6ee2eB44ZGoZ8vg").unwrap();

    let mint = setup_mint(svm, &payer).unwrap();

    let devnet_client = RpcClient::new("https://api.devnet.solana.com".to_string());
    let scope_mapping_registry_acc = devnet_client.get_account(&mapping_pubkey).unwrap();

    let mut scope_mapping_data = scope_mapping_registry_acc.data.clone();
    let mut scope_mapping_registry = ScopeMappingRegistry::from_bytes(
        scope_mapping_data[..ScopeMappingRegistry::LEN]
            .try_into()
            .unwrap(),
    )
    .unwrap();

    // Create new mint mapping
    let new_mint_mapping = MintMapping::new(
        mint.to_bytes(),
        Some([0, u16::MAX, u16::MAX]),
        None,
        None,
        9,
    );

    let mapping_mint_data = new_mint_mapping.to_bytes();
    let mapping = &mapping_mint_data[..new_mint_mapping.serialized_size() as usize];

    let insertion_offset =
        ScopeMappingRegistry::LEN + scope_mapping_registry.last_mapping_offset as usize;

    scope_mapping_data.resize(insertion_offset + mapping.len(), 0);

    scope_mapping_data[insertion_offset..insertion_offset + mapping.len()].copy_from_slice(mapping);

    scope_mapping_registry.total_mappings += 1;
    scope_mapping_registry.last_mapping_offset += mapping.len() as u16;

    scope_mapping_data[..ScopeMappingRegistry::LEN]
        .copy_from_slice(&scope_mapping_registry.to_bytes());

    let data = Account {
        lamports: scope_mapping_registry_acc.lamports + 10000000,
        data: scope_mapping_data,
        owner: owner_pubkey,
        executable: false,
        rent_epoch: 18446744073709551615,
    };

    svm.set_account(mapping_pubkey, data).unwrap();

    // sync litesvm slot to mainnet slot
    let slot = client.get_slot().unwrap();
    svm.warp_to_slot(slot);

    Ok(mint)
}

pub fn advance_slot(context: &mut SwigTestContext, slots: u64) -> u64 {
    use solana_client::rpc_client::RpcClient;

    let client = RpcClient::new("https://api.mainnet-beta.solana.com".to_string());
    let slot = client.get_slot().unwrap();
    let new_slot = slot + slots;
    context.svm.warp_to_slot(new_slot);
    new_slot
}

pub fn setup_mint(svm: &mut LiteSVM, payer: &Keypair) -> anyhow::Result<Pubkey> {
    let mint = CreateMint::new(svm, payer)
        .decimals(9)
        .token_program_id(&spl_token::ID)
        .send()
        .map_err(|e| anyhow::anyhow!("Failed to create mint {:?}", e))?;
    Ok(mint)
}

pub fn setup_oracle_mint(context: &mut SwigTestContext) -> anyhow::Result<Pubkey> {
    load_sample_pyth_accounts(&mut context.svm).unwrap();

    // Setup token accounts
    let mint_key_bytes = [
        193, 17, 76, 51, 120, 6, 8, 131, 149, 6, 187, 31, 102, 121, 14, 198, 202, 133, 249, 221,
        22, 60, 55, 46, 12, 43, 226, 195, 167, 208, 193, 78, 247, 169, 151, 255, 215, 241, 92, 175,
        239, 134, 208, 37, 97, 234, 209, 161, 53, 165, 40, 34, 193, 65, 166, 81, 164, 72, 62, 60,
        149, 224, 228, 83,
    ];
    let mint_kp = Keypair::from_bytes(&mint_key_bytes).unwrap();
    let mint_pubkey = mint_kp.pubkey();
    use solana_program::system_instruction::create_account;
    use solana_sdk::transaction::Transaction;
    use spl_token::instruction::initialize_mint2;
    use spl_token::state::Mint;

    let mint_size = Mint::LEN;

    let ix1 = create_account(
        &context.default_payer.pubkey(),
        &mint_kp.pubkey(),
        context.svm.minimum_balance_for_rent_exemption(mint_size),
        mint_size as u64,
        &spl_token::ID,
    );
    let ix2 = initialize_mint2(
        &spl_token::ID,
        &mint_kp.pubkey(),
        &context.default_payer.pubkey(),
        None,
        9,
    )
    .unwrap();
    let block_hash = context.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix1, ix2],
        Some(&context.default_payer.pubkey()),
        &[&context.default_payer, &mint_kp],
        block_hash,
    );
    let tx_sig = context.svm.send_transaction(tx).unwrap();
    Ok(mint_pubkey)
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

pub fn display_swig(swig_pubkey: Pubkey, data: &[u8], lamports: u64) -> Result<()> {
    let swig_with_roles = SwigWithRoles::from_bytes(data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;

    println!("╔══════════════════════════════════════════════════════════════════");
    println!("║ SWIG WALLET DETAILS");
    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ Account Address: {}", swig_pubkey);
    println!("║ Total Roles: {}", swig_with_roles.state.role_counter);
    println!("║ Balance: {} SOL", lamports as f64 / 1_000_000_000.0);

    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ ROLES & PERMISSIONS");
    println!("╠══════════════════════════════════════════════════════════════════");

    for i in 0..swig_with_roles.state.role_counter {
        let role = swig_with_roles
            .get_role(i)
            .map_err(|e| anyhow::anyhow!("Failed to get role {:?}", e))?;

        if let Some(role) = role {
            println!("║");
            println!("║ Role ID: {}", i);
            println!(
                "║ ├─ Type: {}",
                if role.authority.session_based() {
                    "Session-based Authority"
                } else {
                    "Permanent Authority"
                }
            );
            println!("║ ├─ Authority Type: {:?}", role.authority.authority_type());
            println!(
                "║ ├─ Authority: {}",
                match role.authority.authority_type() {
                    AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority = bs58::encode(authority).into_string();
                        authority
                    },
                    AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority_hex = hex::encode([&[0x4].as_slice(), authority].concat());
                        // get eth address from public key
                        let mut hasher = solana_sdk::keccak::Hasher::default();
                        hasher.hash(authority_hex.as_bytes());
                        let hash = hasher.result();
                        let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                        format!(
                            "{} \n║ │  ├─ odometer: {:?}",
                            address,
                            role.authority.signature_odometer()
                        )
                    },
                    AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority_hex = hex::encode(authority);
                        format!(
                            "Secp256r1: {} \n║ │  ├─ odometer: {:?}",
                            authority_hex,
                            role.authority.signature_odometer()
                        )
                    },
                    _ => "Unknown authority type".to_string(),
                }
            );

            println!("║ ├─ Permissions:");

            // Check All permission
            if (Role::get_action::<All>(&role, &[])
                .map_err(|_| anyhow::anyhow!("Failed to get action"))?)
            .is_some()
            {
                println!("║ │  ├─ Full Access (All Permissions)");
            }

            // Check Manage Authority permission
            if (Role::get_action::<ManageAuthority>(&role, &[])
                .map_err(|_| anyhow::anyhow!("Failed to get action"))?)
            .is_some()
            {
                println!("║ │  ├─ Manage Authority");
            }

            // Check Oracle limit
            let actions = Role::get_all_actions_of_type::<OracleTokenLimit>(&role)
                .map_err(|_| anyhow::anyhow!("Failed to get action"))?;
            if !actions.is_empty() {
                println!("║ │  ├─ Oracle Token Limit:");
                for action in actions {
                    println!(
                        "║ │  │  ├─ Oracle Base Asset: {}",
                        match action.base_asset_type {
                            0 => "USD",
                            1 => "EUR",
                            _ => "Unknown",
                        }
                    );
                    println!(
                        "║ │  │  ├─ Value Limit: {}",
                        action.value_limit as f64
                            / 10_f64.powf(action.get_base_asset_decimals() as f64)
                    );
                    println!(
                        "║ │  │  ├─ Passthrough Check Enabled: {}",
                        action.passthrough_check
                    );
                }
            }

            let actions = Role::get_all_actions_of_type::<OracleRecurringLimit>(&role)
                .map_err(|_| anyhow::anyhow!("Failed to get action"))?;
            if !actions.is_empty() {
                println!("║ │  ├─ Oracle Recurring Limit:");
                for action in actions {
                    println!(
                        "║ │  ├─ Oracle Base Asset: {}",
                        match action.base_asset_type {
                            0 => "USD",
                            1 => "EUR",
                            _ => "Unknown",
                        }
                    );
                    println!(
                        "║ │  │  ├─ Value Limit: {}",
                        action.recurring_value_limit as f64
                            / 10_f64.powf(action.get_base_asset_decimals() as f64)
                    );
                    println!("║ │  │  ├─ Window: {} slots", action.window);
                    println!(
                        "║ │  │  ├─ Current Usage: {}",
                        action.current_amount as f64
                            / 10_f64.powf(action.get_base_asset_decimals() as f64)
                    );
                    println!("║ │  │  └─ Last Reset: Slot {}", action.last_reset);
                }
            }

            // Check Sol Limit
            if let Some(action) = Role::get_action::<SolLimit>(&role, &[])
                .map_err(|_| anyhow::anyhow!("Failed to get action"))?
            {
                println!(
                    "║ │  ├─ SOL Limit: {} SOL",
                    action.amount as f64 / 1_000_000_000.0
                );
            }

            // Check Sol Recurring Limit
            if let Some(action) = Role::get_action::<SolRecurringLimit>(&role, &[])
                .map_err(|_| anyhow::anyhow!("Failed to get action"))?
            {
                println!("║ │  ├─ Recurring SOL Limit:");
                println!(
                    "║ │  │  ├─ Amount: {} SOL",
                    action.recurring_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  ├─ Window: {} slots", action.window);
                println!(
                    "║ │  │  ├─ Current Usage: {} SOL",
                    action.current_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  └─ Last Reset: Slot {}", action.last_reset);
            }

            println!("║ │  ");
        }
    }

    println!("╚══════════════════════════════════════════════════════════════════");

    Ok(())
}
