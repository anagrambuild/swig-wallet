#[cfg(test)]
use litesvm::LiteSVM;
use solana_client::{rpc_client::RpcClient, rpc_request::TokenAccountsFilter};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_sdk::{
    account::ReadableAccount,
    clock::Clock,
    commitment_config::CommitmentConfig,
    message::{v0, AddressLookupTableAccount, VersionedMessage},
    pubkey::{self, ParsePubkeyError},
    rent::Rent,
    signature::{Keypair, Signature, Signer},
    system_instruction::{self, SystemInstruction},
    transaction::{Transaction, VersionedTransaction},
};
use swig_interface::{swig, swig_key};
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit,
    },
    authority::{self, AuthorityType},
    role::Role,
    swig::SwigWithRoles,
};

use crate::{
    error::SwigError,
    instruction_builder::{AuthorityManager, SwigInstructionBuilder},
    types::Permission,
    RecurringConfig,
};
pub struct SwigWallet<'a> {
    /// The underlying instruction builder
    instruction_builder: SwigInstructionBuilder,
    /// RPC client for interacting with the Solana network
    pub rpc_client: RpcClient,
    /// The wallet's fee payer
    fee_payer: &'a Keypair,
    /// Authority keypair
    authority: &'a Keypair,
    /// The LiteSVM instance for testing
    #[cfg(test)]
    litesvm: LiteSVM,
}

impl<'c> SwigWallet<'c> {
    /// Creates a new SwigWallet instance
    ///
    /// # Arguments
    /// * `swig_account` - The public key of the Swig account
    /// * `authority` - The wallet's authority credentials
    /// * `fee_payer` - The keypair that will pay for transactions
    /// * `role_id` - The role id for this wallet
    /// * `rpc_url` - The URL of the Solana RPC endpoint
    pub fn new(
        swig_id: [u8; 32],
        authority_manager: AuthorityManager,
        fee_payer: &'c Keypair,
        authority: &'c Keypair,
        rpc_url: String,
        #[cfg(test)] mut litesvm: LiteSVM,
    ) -> Result<Self, SwigError> {
        let rpc_client =
            RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

        // Check if the Swig account already exists
        let swig_account = SwigInstructionBuilder::swig_key(&swig_id);

        #[cfg(not(test))]
        let swig_data = rpc_client.get_account_data(&swig_account);
        #[cfg(test)]
        let swig_data = litesvm.get_account(&swig_account);

        #[cfg(not(test))]
        let account_exists = swig_data.is_ok();
        #[cfg(test)]
        let account_exists = swig_data.is_some();

        if !account_exists {
            #[cfg(test)]
            println!("Swig account does not exist, creating new one");
            let instruction_builder =
                SwigInstructionBuilder::new(swig_id, authority_manager, fee_payer.pubkey(), 0);

            let create_ix = instruction_builder.build_swig_account()?;

            let msg = v0::Message::try_compile(
                &fee_payer.pubkey(),
                &[create_ix],
                &[],
                #[cfg(not(test))]
                rpc_client.get_latest_blockhash()?,
                #[cfg(test)]
                litesvm.latest_blockhash(),
            )?;

            let tx = VersionedTransaction::try_new(
                VersionedMessage::V0(msg),
                &[fee_payer.insecure_clone()],
            )?;

            #[cfg(not(test))]
            let signature = rpc_client.send_and_confirm_transaction(&tx)?;
            #[cfg(test)]
            let signature = litesvm.send_transaction(tx).unwrap().signature;

            Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer,
                authority,
                #[cfg(test)]
                litesvm,
            })
        } else {
            #[cfg(test)]
            println!("Swig account already exists");

            // Safe unwrap because we know the account exists
            #[cfg(not(test))]
            let swig_data = swig_data.unwrap();
            #[cfg(test)]
            let swig_data = swig_data.unwrap().data;

            let swig_with_roles =
                SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

            let role_id = match &authority_manager {
                AuthorityManager::Ed25519(authority) => swig_with_roles
                    .lookup_role_id(authority.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
                AuthorityManager::Secp256k1(authority, _) => swig_with_roles
                    .lookup_role_id(authority.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
                AuthorityManager::Ed25519Session(session_authority) => swig_with_roles
                    .lookup_role_id(session_authority.public_key.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
                AuthorityManager::Secp256k1Session(session_authority, _) => swig_with_roles
                    .lookup_role_id(session_authority.public_key.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
            }
            .ok_or(SwigError::AuthorityNotFound)?;

            // Get the role to verify it exists and has the correct type
            let role = swig_with_roles
                .get_role(role_id)
                .map_err(|_| SwigError::AuthorityNotFound)?;

            if let Some(role) = role {
                println!("Role found: {:?}", role.actions);
            } else {
                println!("Role not found");
            }

            let instruction_builder = SwigInstructionBuilder::new(
                swig_id,
                authority_manager,
                fee_payer.pubkey(),
                role_id,
            );

            Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer: &fee_payer,
                authority: &authority,
                #[cfg(test)]
                litesvm,
            })
        }
    }

    /// Adds a new authority to the wallet
    ///
    /// # Arguments
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials
    /// * `permissions` - Vector of permissions to grant to the new authority
    pub fn add_authority(
        &mut self,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<Permission>,
    ) -> Result<Signature, SwigError> {
        let instruction = self.instruction_builder.add_authority_instruction(
            new_authority_type,
            new_authority,
            permissions,
            None,
        )?;
        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &[instruction],
            &[],
            #[cfg(not(test))]
            self.rpc_client.get_latest_blockhash()?,
            #[cfg(test)]
            self.litesvm.latest_blockhash(),
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)
    }

    /// Removes an authority from the wallet
    ///
    /// # Arguments
    /// * `authority` - The authority to remove
    pub fn remove_authority(&mut self, authority: &[u8]) -> Result<Signature, SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(test))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(test)]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;
        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        let authority_id = swig_with_roles.lookup_role_id(authority.as_ref()).unwrap();

        if let Some(authority_id) = authority_id {
            let instruction = self
                .instruction_builder
                .remove_authority(authority_id, None)?;

            let msg = v0::Message::try_compile(
                &self.fee_payer.pubkey(),
                &[instruction],
                &[],
                #[cfg(not(test))]
                self.rpc_client.get_latest_blockhash()?,
                #[cfg(test)]
                self.litesvm.latest_blockhash(),
            )?;

            let tx = VersionedTransaction::try_new(
                VersionedMessage::V0(msg),
                &[self.fee_payer.insecure_clone()],
            )?;

            self.send_and_confirm_transaction(tx)
        } else {
            return Err(SwigError::AuthorityNotFound);
        }
    }

    /// Signs a transaction with the given instructions
    ///
    /// # Arguments
    /// * `inner_instructions` - The instructions to sign
    pub fn sign(
        &mut self,
        inner_instructions: Vec<Instruction>,
        alt: Option<&[AddressLookupTableAccount]>,
    ) -> Result<Signature, SwigError> {
        let sign_ix = self
            .instruction_builder
            .sign_instruction(inner_instructions, Some(self.get_current_slot()?))?;

        let alt = if alt.is_some() { alt.unwrap() } else { &[] };

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &sign_ix,
            alt,
            #[cfg(not(test))]
            self.rpc_client.get_latest_blockhash()?,
            #[cfg(test)]
            self.litesvm.latest_blockhash(),
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[&self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)
    }

    /// Replaces an existing authority
    ///
    /// # Arguments
    /// * `authority_to_replace_id` - The ID of the authority to replace
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials
    /// * `permissions` - Vector of permissions to grant to the new authority
    pub fn replace_authority(
        &mut self,
        authority_to_replace_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<Permission>,
    ) -> Result<Signature, SwigError> {
        let instructions = self.instruction_builder.replace_authority(
            authority_to_replace_id,
            new_authority_type,
            new_authority,
            permissions,
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &instructions,
            &[],
            self.rpc_client.get_latest_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)
    }

    /// Signs and executes a transaction with the given instructions
    ///
    /// # Arguments
    /// * `instructions` - The instructions to include in the transaction
    fn send_and_confirm_transaction(
        &mut self,
        tx: VersionedTransaction,
    ) -> Result<Signature, SwigError> {
        #[cfg(not(test))]
        let signature = self.rpc_client.send_and_confirm_transaction(&tx)?;
        #[cfg(test)]
        let signature = self
            .litesvm
            .send_transaction(tx)
            .map_err(|e| SwigError::TransactionFailed(e.err.to_string()))?
            .signature;

        Ok(signature)
    }

    /// Returns the public key of the Swig account
    pub fn get_swig_account(&self) -> Result<Pubkey, SwigError> {
        self.instruction_builder.get_swig_account()
    }

    /// Returns the permissions of the authority of the Swig account
    pub fn get_current_authority_permissions(&self) -> Result<Vec<Permission>, SwigError> {
        let swig_pubkey = self.get_swig_account()?;

        #[cfg(not(test))]
        let swig_account = self.rpc_client.get_account(&swig_pubkey)?;
        #[cfg(test)]
        let swig_account = self.litesvm.get_account(&swig_pubkey).unwrap();

        #[cfg(not(test))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(test)]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;
        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        let mut permissions: Vec<Permission> = Vec::new();
        for i in 0..swig_with_roles.state.role_counter {
            let role = swig_with_roles.get_role(i).unwrap();
            if let Some(role) = role {
                if role
                    .authority
                    .match_data(self.instruction_builder.get_current_authority()?.as_ref())
                {
                    println!("Role {} matches", i);
                    if (Role::get_action::<All>(&role, &[])
                        .map_err(|_| SwigError::AuthorityNotFound)?)
                    .is_some()
                    {
                        permissions.push(Permission::All);
                    }
                    // Sol Limit
                    if let Some(action) = Role::get_action::<SolLimit>(&role, &[])
                        .map_err(|_| SwigError::AuthorityNotFound)?
                    {
                        permissions.push(Permission::Sol {
                            amount: action.amount,
                            recurring: None,
                        });
                    }
                    // Sol Recurring
                    if let Some(action) = Role::get_action::<SolRecurringLimit>(&role, &[])
                        .map_err(|_| SwigError::AuthorityNotFound)?
                    {
                        permissions.push(Permission::Sol {
                            amount: action.recurring_amount,
                            recurring: Some(RecurringConfig {
                                window: action.window,
                                last_reset: action.last_reset,
                                current_amount: action.current_amount,
                            }),
                        });
                    }
                    // Manage Authority
                    if (Role::get_action::<ManageAuthority>(&role, &[])
                        .map_err(|_| SwigError::AuthorityNotFound)?)
                    .is_some()
                    {
                        println!("\t\tManage Authority permission exists");
                    }
                }
            }
        }
        Ok(permissions)
    }

    /// Prints the Swig account
    pub fn display_swig(&self) -> Result<(), SwigError> {
        let swig_pubkey = self.get_swig_account()?;

        #[cfg(not(test))]
        let swig_account = self.rpc_client.get_account(&swig_pubkey)?;
        #[cfg(test)]
        let swig_account = self.litesvm.get_account(&swig_pubkey).unwrap();

        #[cfg(not(test))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(test)]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;

        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        println!("╔══════════════════════════════════════════════════════════════════");
        println!("║ SWIG WALLET DETAILS");
        println!("╠══════════════════════════════════════════════════════════════════");
        println!("║ Account Address: {}", swig_pubkey);
        println!("║ Total Roles: {}", swig_with_roles.state.role_counter);
        println!(
            "║ Balance: {} SOL",
            swig_account.lamports() as f64 / 1_000_000_000.0
        );
        println!("╠══════════════════════════════════════════════════════════════════");
        println!("║ ROLES & PERMISSIONS");
        println!("╠══════════════════════════════════════════════════════════════════");

        for i in 0..swig_with_roles.state.role_counter {
            let role = swig_with_roles
                .get_role(i)
                .map_err(|e| SwigError::AuthorityNotFound)?;

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
                            let authority_hex =
                                hex::encode([&[0x4].as_slice(), authority].concat());
                            //get eth address from public key
                            let mut hasher = solana_sdk::keccak::Hasher::default();
                            hasher.hash(authority);
                            let hash = hasher.result();
                            let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                            address
                        },
                        _ => todo!(),
                    }
                );

                println!("║ ├─ Permissions:");

                // Check All permission
                if (Role::get_action::<All>(&role, &[])
                    .map_err(|_| SwigError::AuthorityNotFound)?)
                .is_some()
                {
                    println!("║ │  ├─ Full Access (All Permissions)");
                }

                // Check Manage Authority permission
                if (Role::get_action::<ManageAuthority>(&role, &[])
                    .map_err(|_| SwigError::AuthorityNotFound)?)
                .is_some()
                {
                    println!("║ │  ├─ Manage Authority");
                }

                // Check Sol Limit
                if let Some(action) = Role::get_action::<SolLimit>(&role, &[])
                    .map_err(|_| SwigError::AuthorityNotFound)?
                {
                    println!(
                        "║ │  ├─ SOL Limit: {} SOL",
                        action.amount as f64 / 1_000_000_000.0
                    );
                }

                // Check Sol Recurring Limit
                if let Some(action) = Role::get_action::<SolRecurringLimit>(&role, &[])
                    .map_err(|_| SwigError::AuthorityNotFound)?
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

    /// Switches the authority of the Swig account
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to switch to
    /// * `authority` - The new authority's credentials
    pub fn switch_authority(&mut self, role_id: u32, authority: Pubkey) -> Result<(), SwigError> {
        self.instruction_builder
            .switch_authority(role_id, authority)?;
        Ok(())
    }

    /// Switches the payer of the Swig account
    ///
    /// # Arguments
    /// * `payer` - The new payer's credentials
    pub fn switch_payer(&mut self, payer: &'c Keypair) -> Result<(), SwigError> {
        self.instruction_builder.switch_payer(payer.pubkey())?;
        self.fee_payer = payer;
        Ok(())
    }

    /// Authenticate the authority of the Swig account
    pub fn authenticate_authority(&self, authority: &[u8]) -> Result<(), SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(test))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(test)]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;
        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        let indexed_authority = swig_with_roles.lookup_role_id(authority.as_ref()).unwrap();

        println!("Indexed Authority: {:?}", indexed_authority);
        Ok(())
    }

    /// Create a session for the authority
    pub fn create_session(&mut self, session_key: Pubkey, duration: u64) -> Result<(), SwigError> {
        let current_slot = self.get_current_slot()?;
        let create_session_ix = self.instruction_builder.create_session_instruction(
            session_key,
            duration,
            Some(current_slot),
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &[create_session_ix],
            &[],
            #[cfg(not(test))]
            self.rpc_client.get_latest_blockhash()?,
            #[cfg(test)]
            self.litesvm.latest_blockhash(),
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[&self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)?;
        Ok(())
    }

    pub fn get_current_slot(&self) -> Result<u64, SwigError> {
        #[cfg(not(test))]
        let slot = self.rpc_client.get_slot()?;
        #[cfg(test)]
        let slot = self.litesvm.get_sysvar::<Clock>().slot;
        Ok(slot)
    }

    pub fn get_balance(&self) -> Result<u64, SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(test))]
        let balance = self.rpc_client.get_balance(&swig_pubkey)?;
        #[cfg(test)]
        let balance = self.litesvm.get_balance(&swig_pubkey).unwrap();
        Ok(balance)
    }

    #[cfg(test)]
    pub fn litesvm(&mut self) -> &mut LiteSVM {
        &mut self.litesvm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::LocalSigner;
    use authority::{
        ed25519::CreateEd25519SessionAuthority, secp256k1::CreateSecp256k1SessionAuthority,
    };

    fn setup_litesvm() -> (LiteSVM, Keypair) {
        let mut litesvm = LiteSVM::new();
        let main_authority = Keypair::new();

        litesvm
            .add_program_from_file(Pubkey::new_from_array(swig::ID), "../target/deploy/swig.so")
            .map_err(|_| anyhow::anyhow!("Failed to load program"))
            .unwrap();
        litesvm
            .airdrop(&main_authority.pubkey(), 10_000_000_000)
            .unwrap();

        (litesvm, main_authority)
    }

    #[test]
    fn test_create_ed25519_session() {
        let (mut litesvm, main_authority) = setup_litesvm();

        let session_key = Keypair::new();
        // 1. Create a session based authority
        let mut swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Ed25519Session(CreateEd25519SessionAuthority::new(
                main_authority.pubkey().to_bytes(),
                session_key.pubkey().to_bytes(),
                100,
            )),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        let swig_pubkey = swig_wallet.get_swig_account().unwrap();

        swig_wallet
            .litesvm()
            .airdrop(&swig_pubkey, 10_000_000_000)
            .unwrap();

        // Start a session
        let session_key = Keypair::new();

        swig_wallet
            .create_session(session_key.pubkey(), 100)
            .unwrap();

        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn test_create_secp256k1_session() {
        let (mut litesvm, main_authority) = setup_litesvm();

        let session_key = Keypair::new();

        let wallet = LocalSigner::random();
        let secp_pubkey = wallet
            .credential()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();

        let mut sign_fn = move |payload: &[u8]| -> [u8; 65] {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&payload[..32]);
            let hash = B256::from(hash);
            wallet.sign_hash_sync(&hash).unwrap().as_bytes()
        };

        let swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Secp256k1Session(
                CreateSecp256k1SessionAuthority::new(
                    secp_pubkey[1..].try_into().unwrap(),
                    [0; 32],
                    100,
                ),
                Box::new(sign_fn),
            ),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn test_wallet_creation() {
        let (mut litesvm, main_authority) = setup_litesvm();

        let main_auth_pubkey = main_authority.pubkey();
        let swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Ed25519(main_auth_pubkey),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        // Verify the wallet was created successfully
        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn test_wallet_creation_secp256k1() {
        let (mut litesvm, main_authority) = setup_litesvm();

        let wallet = LocalSigner::random();
        let secp_pubkey = wallet
            .credential()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();
        let wallet = wallet;
        let mut sign_fn = move |payload: &[u8]| -> [u8; 65] {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&payload[..32]);
            let hash = B256::from(hash);
            let tsig = wallet
                .sign_hash_sync(&hash)
                .map_err(|_| SwigError::InvalidSecp256k1)
                .unwrap()
                .as_bytes();
            let mut sig = [0u8; 65];
            sig.copy_from_slice(&tsig);
            sig
        };

        let swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Secp256k1(secp_pubkey, Box::new(sign_fn)),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        // Verify the wallet was created successfully
        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn test_add_authority() {
        let (mut litesvm, main_authority) = setup_litesvm();
        let secondary_authority = Keypair::new();

        let mut swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Ed25519(main_authority.pubkey()),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        // Add secondary authority with SOL permission
        swig_wallet
            .add_authority(
                AuthorityType::Ed25519,
                &secondary_authority.pubkey().to_bytes(),
                vec![Permission::Sol {
                    amount: 10_000_000_000,
                    recurring: None,
                }],
            )
            .unwrap();

        // Verify both authorities exist
        swig_wallet.display_swig().unwrap();

        swig_wallet
            .remove_authority(&secondary_authority.pubkey().to_bytes())
            .unwrap();

        swig_wallet.display_swig().unwrap();

        let third_authority = Keypair::new();

        swig_wallet
            .authenticate_authority(&third_authority.pubkey().to_bytes())
            .unwrap();

        swig_wallet
            .add_authority(
                AuthorityType::Ed25519,
                &third_authority.pubkey().to_bytes(),
                vec![Permission::Sol {
                    amount: 10_000_000_000,
                    recurring: Some(RecurringConfig::new(100)),
                }],
            )
            .unwrap();

        swig_wallet.display_swig().unwrap();

        swig_wallet
            .switch_authority(1, third_authority.pubkey())
            .unwrap();

        swig_wallet
            .authenticate_authority(&third_authority.pubkey().to_bytes())
            .unwrap();
    }

    #[test]
    fn test_switch_authority_and_payer() {
        let (mut litesvm, main_authority) = setup_litesvm();
        let secondary_authority = Keypair::new();
        litesvm
            .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
            .unwrap();

        let mut swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Ed25519(main_authority.pubkey()),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        // Add and switch to secondary authority
        swig_wallet
            .add_authority(
                AuthorityType::Ed25519,
                &secondary_authority.pubkey().to_bytes(),
                vec![Permission::Sol {
                    amount: 10_000_000_000,
                    recurring: Some(RecurringConfig::new(100)),
                }],
            )
            .unwrap();

        swig_wallet
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();

        swig_wallet.switch_payer(&secondary_authority).unwrap();

        // Verify the switch was successful
        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn test_transfer_functionality() {
        let (mut litesvm, main_authority) = setup_litesvm();
        let secondary_authority = Keypair::new();
        litesvm
            .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
            .unwrap();

        let mut swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Ed25519(main_authority.pubkey()),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        // Setup secondary authority with permissions
        swig_wallet
            .add_authority(
                AuthorityType::Ed25519,
                &secondary_authority.pubkey().to_bytes(),
                vec![Permission::Sol {
                    amount: 1_000_000_000,
                    recurring: None,
                }],
            )
            .unwrap();

        swig_wallet
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();
        swig_wallet.switch_payer(&secondary_authority).unwrap();

        let swig_account = swig_wallet.get_swig_account().unwrap();

        // Test transfer
        let recipient = Keypair::new();
        let transfer_ix =
            system_instruction::transfer(&swig_account, &recipient.pubkey(), 100_000_000);

        swig_wallet
            .litesvm()
            .airdrop(&swig_account, 5_000_000_000)
            .unwrap();

        swig_wallet.sign(vec![transfer_ix], None).unwrap();

        // Verify the transfer was successful
        swig_wallet.display_swig().unwrap();
    }

    #[test]
    fn test_transfer_failure() {
        let (mut litesvm, main_authority) = setup_litesvm();
        let secondary_authority = Keypair::new();
        litesvm
            .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
            .unwrap();

        let mut swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityManager::Ed25519(main_authority.pubkey()),
            &main_authority,
            &main_authority,
            "http://localhost:8899".to_string(),
            litesvm,
        )
        .unwrap();

        // Add secondary authority with SOL permission
        swig_wallet
            .add_authority(
                AuthorityType::Ed25519,
                &secondary_authority.pubkey().to_bytes(),
                vec![Permission::Sol {
                    amount: 1_000_000_000,
                    recurring: None,
                }],
            )
            .unwrap();

        swig_wallet
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();
        swig_wallet.switch_payer(&secondary_authority).unwrap();

        let recipient = Keypair::new();
        let transfer_ix = system_instruction::transfer(
            &swig_wallet.get_swig_account().unwrap(),
            &recipient.pubkey(),
            2_000_000_000,
        );

        let result = swig_wallet.sign(vec![transfer_ix], None);
        assert!(result.is_err());
    }
}
