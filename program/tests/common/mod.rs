use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use anyhow::{Ok, Result};
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::{spl_token, CreateAssociatedTokenAccount, CreateMint, MintTo};
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

    let mapping_pubkey = Pubkey::from_str("Chpu5ZgfWX5ZzVpUx9Xvv4WPM75Xd7zPJNDPsFnCpLpk").unwrap();
    let owner_pubkey = Pubkey::from_str("HFn8GnPADiny6XqUoWE8uRPPxb29ikn4yTuPa9MF2fWJ").unwrap();

    let mint = setup_mint(svm, &payer).unwrap();

    data = Account {
        lamports: 200_700_000,
        data: get_mapping_data(&mint, 9, 153),
        owner: owner_pubkey,
        executable: false,
        rent_epoch: 18446744073709551615,
    };

    svm.set_account(mapping_pubkey, data).unwrap();

    Ok(mint)
}

use std::str::FromStr;

fn get_mapping_data(token_pubkey: &Pubkey, token_decimals: u8, token_index: u16) -> Vec<u8> {
    let sol_pubkey = Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap();
    let mut pyth_data = [0; 33];
    let mut pyth_account = Pubkey::from_str("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE")
        .unwrap()
        .to_bytes();
    pyth_data[0] = 1;
    pyth_data[1..33].copy_from_slice(&pyth_account);

    let mut switch_data = [0; 33];
    let mut switch_board = Pubkey::from_str("7yyaeuJ1GGtVBLT2z2xub5ZWYKaNhF28mj1RdV4VDFVk")
        .unwrap()
        .to_bytes();
    switch_data[0] = 1;
    switch_data[1..33].copy_from_slice(&switch_board);

    let sol_mapping = MintMapping {
        mint: sol_pubkey.to_bytes(),
        price_chain: [0, u16::MAX, u16::MAX, u16::MAX], // SOL price chain
        decimals: 9,                                    // SOL has 9 decimals
        is_active: true,
        pyth_account: pyth_data,
        switch_board: switch_data,
    };

    let token_mapping = MintMapping {
        mint: token_pubkey.to_bytes(),
        price_chain: [token_index, u16::MAX, u16::MAX, u16::MAX], // SOL price chain
        decimals: token_decimals,                                 // SOL has 9 decimals
        is_active: true,
        pyth_account: pyth_data,
        switch_board: switch_data,
    };

    let scope_mapping_registry = ScopeMappingRegistry {
        is_initialized: 1,
        owner: Pubkey::from_str("3NJYftD5sjVfxSnUdZ1wVML8f3aC6mp1CXCL6L7TnU8C")
            .unwrap()
            .to_bytes(),
        total_mappings: 2,
        version: 2,
        bump: 0,
    };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&scope_mapping_registry.to_bytes());
    bytes.extend_from_slice(&sol_mapping.to_bytes());
    bytes.extend_from_slice(&token_mapping.to_bytes());

    bytes
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MintMapping {
    pub mint: [u8; 32],
    pub price_chain: [u16; 4], // Conversion chain (e.g., [32, 0, u16::MAX, u16::MAX])
    pub decimals: u8,          // Mint decimals for price calculations
    pub is_active: bool,
    pub pyth_account: [u8; 33], // 0 = None, 1 = Some + 32 bytes
    pub switch_board: [u8; 33], // 0 = None, 1 = Some + 32 bytes
}

impl Default for MintMapping {
    fn default() -> Self {
        Self {
            mint: [0u8; 32],
            price_chain: [0u16; 4],
            decimals: 0,
            is_active: false,
            pyth_account: [0u8; 33],
            switch_board: [0u8; 33],
        }
    }
}

impl MintMapping {
    const LEN: usize = core::mem::size_of::<MintMapping>();

    pub fn set_pyth_account(&mut self, value: Option<[u8; 32]>) {
        match value {
            Some(val) => {
                self.pyth_account[0] = 1;
                self.pyth_account[1..].copy_from_slice(&val);
            },
            None => {
                self.pyth_account[0] = 0;
                self.pyth_account[1..].fill(0);
            },
        }
    }

    pub fn get_pyth_account(&self) -> Option<[u8; 32]> {
        if self.pyth_account[0] == 1 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self.pyth_account[1..]);
            Some(arr)
        } else {
            None
        }
    }

    pub fn set_switch_board(&mut self, value: Option<[u8; 32]>) {
        match value {
            Some(val) => {
                self.switch_board[0] = 1;
                self.switch_board[1..].copy_from_slice(&val);
            },
            None => {
                self.switch_board[0] = 0;
                self.switch_board[1..].fill(0);
            },
        }
    }

    pub fn get_switch_board(&self) -> Option<[u8; 32]> {
        if self.switch_board[0] == 1 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self.switch_board[1..]);
            Some(arr)
        } else {
            None
        }
    }

    /// Load a MintMapping from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        if bytes.len() != Self::LEN {
            return Err(anyhow::anyhow!("Invalid byte length"));
        }

        // SAFETY: We've verified the byte length matches the struct size
        // and we're using #[repr(C)] which guarantees stable memory layout
        let mapping = unsafe { *(bytes.as_ptr() as *const Self) };
        Ok(mapping)
    }

    /// Convert a MintMapping to a byte array
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];

        // SAFETY: We're using #[repr(C)] which guarantees stable memory layout
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                Self::LEN,
            );
        }
        bytes
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, shank::ShankAccount)]
pub struct ScopeMappingRegistry {
    pub is_initialized: u8,
    pub owner: [u8; 32],
    pub total_mappings: u32,
    pub version: u8,
    pub bump: u8,
    // Remove the fixed array and we'll handle mappings separately
}

impl ScopeMappingRegistry {
    const LEN: usize = core::mem::size_of::<ScopeMappingRegistry>();

    /// Load a ScopeMappingRegistry from a byte array
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Result<Self, anyhow::Error> {
        if bytes.len() != Self::LEN {
            return Err(anyhow::anyhow!("Invalid byte length"));
        }

        // SAFETY: We've verified the byte length matches the struct size
        // and we're using #[repr(C)] which guarantees stable memory layout
        let mapping = unsafe { *(bytes.as_ptr() as *const Self) };
        Ok(mapping)
    }

    /// Convert a ScopeMappingRegistry to a byte array
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];

        // SAFETY: We're using #[repr(C)] which guarantees stable memory layout
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                Self::LEN,
            );
        }
        bytes
    }

    /// Load a ScopeMappingRegistry from a slice of bytes
    pub fn from_slice(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        if bytes.len() != Self::LEN {
            return Err(anyhow::anyhow!("Invalid byte length"));
        }

        // SAFETY: We've verified the byte length matches the struct size
        let mapping = unsafe { *(bytes.as_ptr() as *const Self) };
        Ok(mapping)
    }

    /// Convert a ScopeMappingRegistry to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes.to_vec()
    }

    /// Given the full account data, split into registry and mappings vector
    pub fn from_account_data(data: &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() < Self::LEN {
            return Err(anyhow::anyhow!("Invalid byte length"));
        }
        let registry = Self::from_slice(&data[..Self::LEN])?;
        Ok(registry)
    }

    /// Write the registry and mappings vector to the account data
    pub fn to_account_data(
        registry: &Self,
        mapping: &MintMapping,
        data: &mut [u8],
    ) -> Result<(), anyhow::Error> {
        let reg_bytes = registry.to_bytes();
        data[..Self::LEN].copy_from_slice(&reg_bytes);
        let mapping_bytes = mapping.to_bytes();
        data[Self::LEN..Self::LEN + MintMapping::LEN].copy_from_slice(&mapping_bytes);
        Ok(())
    }

    /// Get the mappings slice from the account data
    pub fn get_mappings_slice(data: &[u8]) -> Result<&[u8], anyhow::Error> {
        if data.len() < Self::LEN {
            return Err(anyhow::anyhow!("Invalid byte length"));
        }
        Ok(&data[Self::LEN..])
    }
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
