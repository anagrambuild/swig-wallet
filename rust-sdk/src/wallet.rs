#[cfg(all(feature = "rust_sdk_test", test))]
use litesvm::LiteSVM;
use solana_client::{rpc_client::RpcClient, rpc_request::TokenAccountsFilter};
use solana_program::hash::Hash;
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_sdk::{
    account::ReadableAccount,
    address_lookup_table::{state::AddressLookupTable, AddressLookupTableAccount},
    clock::Clock,
    commitment_config::CommitmentConfig,
    message::{v0, VersionedMessage},
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

/// Swig protocol for transaction signing and authority management.
///
/// This struct provides methods for interacting with a Swig wallet on chain,
pub struct SwigWallet<'a> {
    /// The underlying instruction builder for creating Swig instructions
    instruction_builder: SwigInstructionBuilder,
    /// RPC client for interacting with the Solana network
    pub rpc_client: RpcClient,
    /// The wallet's fee payer keypair
    fee_payer: &'a Keypair,
    /// The authority keypair for signing transactions
    authority: &'a Keypair,
    /// The LiteSVM instance for testing
    #[cfg(all(feature = "rust_sdk_test", test))]
    litesvm: LiteSVM,
}

impl<'c> SwigWallet<'c> {
    /// Creates a new SwigWallet instance or initializes an existing one
    ///
    /// # Arguments
    ///
    /// * `swig_id` - The unique identifier for the Swig account
    /// * `authority_manager` - The authority manager specifying the type of signing authority
    /// * `fee_payer` - The keypair that will pay for transactions
    /// * `authority` - The wallet's authority keypair
    /// * `rpc_url` - The URL of the Solana RPC endpoint
    /// * `litesvm` - (test only) The LiteSVM instance for testing
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the new `SwigWallet` instance or a `SwigError`
    pub fn new(
        swig_id: [u8; 32],
        authority_manager: AuthorityManager,
        fee_payer: &'c Keypair,
        authority: &'c Keypair,
        rpc_url: String,
        #[cfg(all(feature = "rust_sdk_test", test))] mut litesvm: LiteSVM,
    ) -> Result<Self, SwigError> {
        let rpc_client =
            RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

        // Check if the Swig account already exists
        let swig_account = SwigInstructionBuilder::swig_key(&swig_id);

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = rpc_client.get_account_data(&swig_account);
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_data = litesvm.get_account(&swig_account);

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let account_exists = swig_data.is_ok();
        #[cfg(all(feature = "rust_sdk_test", test))]
        let account_exists = swig_data.is_some();

        if !account_exists {
            let instruction_builder =
                SwigInstructionBuilder::new(swig_id, authority_manager, fee_payer.pubkey(), 0);

            let create_ix = instruction_builder.build_swig_account()?;

            #[cfg(not(all(feature = "rust_sdk_test", test)))]
            let blockhash = rpc_client.get_latest_blockhash()?;
            #[cfg(all(feature = "rust_sdk_test", test))]
            let blockhash = litesvm.latest_blockhash();

            let msg = v0::Message::try_compile(&fee_payer.pubkey(), &[create_ix], &[], blockhash)?;

            let tx = VersionedTransaction::try_new(
                VersionedMessage::V0(msg),
                &[fee_payer.insecure_clone()],
            )?;

            #[cfg(not(all(feature = "rust_sdk_test", test)))]
            let signature = rpc_client.send_and_confirm_transaction(&tx)?;
            #[cfg(all(feature = "rust_sdk_test", test))]
            let signature = litesvm.send_transaction(tx).unwrap().signature;

            Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer,
                authority,
                #[cfg(all(feature = "rust_sdk_test", test))]
                litesvm,
            })
        } else {
            // Safe unwrap because we know the account exists
            #[cfg(not(all(feature = "rust_sdk_test", test)))]
            let swig_data = swig_data.unwrap();
            #[cfg(all(feature = "rust_sdk_test", test))]
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
                #[cfg(all(feature = "rust_sdk_test", test))]
                litesvm,
            })
        }
    }

    /// Adds a new authority to the wallet with specified permissions
    ///
    /// # Arguments
    ///
    /// * `new_authority_type` - The type of authority to add (Ed25519, Secp256k1, etc.)
    /// * `new_authority` - The new authority's credentials as bytes
    /// * `permissions` - Vector of permissions to grant to the new authority
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
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
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)
    }

    /// Removes an existing authority from the wallet
    ///
    /// # Arguments
    ///
    /// * `authority` - The authority's public key as bytes to remove
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn remove_authority(&mut self, authority: &[u8]) -> Result<Signature, SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
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
                self.get_current_blockhash()?,
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

    /// Signs a transaction containing the provided instructions
    ///
    /// # Arguments
    ///
    /// * `inner_instructions` - Vector of instructions to include in the transaction
    /// * `alt` - Optional slice of Address Lookup Table accounts
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
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
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[&self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)
    }

    /// Replaces an existing authority with a new one
    ///
    /// # Arguments
    ///
    /// * `authority_to_replace_id` - The ID of the authority to replace
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials as bytes
    /// * `permissions` - Vector of permissions to grant to the new authority
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn replace_authority(
        &mut self,
        authority_to_replace_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<Permission>,
    ) -> Result<Signature, SwigError> {
        let current_slot = self.get_current_slot()?;

        let instructions = self.instruction_builder.replace_authority(
            authority_to_replace_id,
            new_authority_type,
            new_authority,
            permissions,
            Some(current_slot),
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &instructions,
            &[],
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)
    }

    /// Sends and confirms a transaction on the Solana network
    ///
    /// # Arguments
    ///
    /// * `tx` - The versioned transaction to send
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    fn send_and_confirm_transaction(
        &mut self,
        tx: VersionedTransaction,
    ) -> Result<Signature, SwigError> {
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let signature = self.rpc_client.send_and_confirm_transaction(&tx)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let signature = self
            .litesvm
            .send_transaction(tx)
            .map_err(|e| SwigError::TransactionFailed(e.err.to_string()))?
            .signature;

        Ok(signature)
    }

    /// Returns the public key of the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the Swig account's public key or a `SwigError`
    pub fn get_swig_account(&self) -> Result<Pubkey, SwigError> {
        self.instruction_builder.get_swig_account()
    }

    /// Retrieves the current authority's permissions from the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of the authority's permissions or a `SwigError`
    pub fn get_current_authority_permissions(&self) -> Result<Vec<Permission>, SwigError> {
        let swig_pubkey = self.get_swig_account()?;

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_account = self.rpc_client.get_account(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_account = self.litesvm.get_account(&swig_pubkey).unwrap();

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
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

    /// Displays detailed information about the Swig wallet
    ///
    /// This includes account details, roles, and permissions for all authorities.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn display_swig(&self) -> Result<(), SwigError> {
        let swig_pubkey = self.get_swig_account()?;

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_account = self.rpc_client.get_account(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_account = self.litesvm.get_account(&swig_pubkey).unwrap();

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
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

    /// Switches to a different authority for the Swig wallet
    ///
    /// # Arguments
    ///
    /// * `role_id` - The new role ID to switch to
    /// * `authority` - The public key of the new authority
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn switch_authority(
        &mut self,
        role_id: u32,
        authority_manager: AuthorityManager,
    ) -> Result<(), SwigError> {
        self.instruction_builder
            .switch_authority(role_id, authority_manager)?;
        Ok(())
    }

    /// Updates the fee payer for the Swig wallet
    ///
    /// # Arguments
    ///
    /// * `payer` - The new fee payer's keypair
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn switch_payer(&mut self, payer: &'c Keypair) -> Result<(), SwigError> {
        self.instruction_builder.switch_payer(payer.pubkey())?;
        self.fee_payer = payer;
        Ok(())
    }

    /// Verifies if the provided authority exists in the Swig wallet
    ///
    /// # Arguments
    ///
    /// * `authority` - The authority's public key as bytes to verify
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError` if the authority is not found
    pub fn authenticate_authority(&self, authority: &[u8]) -> Result<(), SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;
        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        let indexed_authority = swig_with_roles.lookup_role_id(authority.as_ref()).unwrap();

        println!("Indexed Authority: {:?}", indexed_authority);
        if indexed_authority.is_some() {
            Ok(())
        } else {
            Err(SwigError::AuthorityNotFound)
        }
    }

    /// Creates a new session for the current authority
    ///
    /// # Arguments
    ///
    /// * `session_key` - The public key for the new session
    /// * `duration` - The duration of the session in slots
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
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
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[&self.fee_payer.insecure_clone()],
        )?;

        self.send_and_confirm_transaction(tx)?;
        Ok(())
    }

    /// Retrieves the current slot number from the Solana network
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the current slot number or a `SwigError`
    pub fn get_current_slot(&self) -> Result<u64, SwigError> {
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let slot = self.rpc_client.get_slot()?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let slot = self.litesvm.get_sysvar::<Clock>().slot;
        Ok(slot)
    }

    /// Returns the current blockhash from the Solana network
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the current blockhash or a `SwigError`
    pub fn get_current_blockhash(&self) -> Result<Hash, SwigError> {
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let blockhash = self.rpc_client.get_latest_blockhash()?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let blockhash = self.litesvm.latest_blockhash();
        Ok(blockhash)
    }

    /// Returns the SOL balance of the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the balance in lamports or a `SwigError`
    pub fn get_balance(&self) -> Result<u64, SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let balance = self.rpc_client.get_balance(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let balance = self.litesvm.get_balance(&swig_pubkey).unwrap();
        Ok(balance)
    }

    /// Returns a mutable reference to the LiteSVM instance (test only)
    ///
    /// # Returns
    ///
    /// Returns a mutable reference to the LiteSVM instance
    #[cfg(all(feature = "rust_sdk_test", test))]
    pub fn litesvm(&mut self) -> &mut LiteSVM {
        &mut self.litesvm
    }
}

#[cfg(all(feature = "rust_sdk_test", test))]
mod tests {
    use super::*;
    use crate::tests::wallet_tests;
}
