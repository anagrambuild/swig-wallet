use alloy_primitives::{Address, B256};
#[cfg(all(feature = "rust_sdk_test", test))]
use litesvm::LiteSVM;
#[cfg(all(feature = "rust_sdk_test", test))]
use litesvm_token::CreateAssociatedTokenAccount;
use solana_account_decoder_client_types::{ParsedAccount, UiAccountData};
use solana_client::{
    rpc_client::RpcClient, rpc_request::TokenAccountsFilter, rpc_response::RpcKeyedAccount,
};
use solana_program::{hash::Hash, instruction::Instruction, pubkey::Pubkey};
use solana_sdk::{
    account::ReadableAccount,
    address_lookup_table::{state::AddressLookupTable, AddressLookupTableAccount},
    clock::Clock,
    commitment_config::CommitmentConfig,
    message::{v0, VersionedMessage},
    pubkey,
    rent::Rent,
    signature::{Keypair, Signature, Signer},
    system_instruction::{self, SystemInstruction},
    transaction::{Transaction, VersionedTransaction},
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use spl_token::ID as TOKEN_PROGRAM_ID;
use swig_interface::{swig, swig_key};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, program_scope::ProgramScope,
        sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount,
        token_destination_limit::TokenDestinationLimit, token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::{self, secp256k1::Secp256k1Authority, AuthorityType},
    role::Role,
    swig::{sub_account_seeds, Swig, SwigWithRoles},
};
const TOKEN_22_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

use crate::{
    client_role::ClientRole,
    error::SwigError,
    instruction_builder::SwigInstructionBuilder,
    types::{Permission, UpdateAuthorityData},
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
    /// The authority keypair (for Ed25519 authorities)
    authority_keypair: Option<&'a Keypair>,
    /// The current role details for the wallet
    pub current_role: crate::types::CurrentRole,
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
    /// * `client_role` - The client role implementation specifying the type of
    ///   signing authority
    /// * `fee_payer` - The keypair that will pay for transactions
    /// * `rpc_url` - The URL of the Solana RPC endpoint
    /// * `authority_keypair` - Optional authority keypair (required for Ed25519
    ///   authorities)
    /// * `litesvm` - (test only) The LiteSVM instance for testing
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the new `SwigWallet` instance or a
    /// `SwigError`
    pub fn new(
        swig_id: [u8; 32],
        mut client_role: Box<dyn ClientRole>,
        fee_payer: &'c Keypair,
        rpc_url: String,
        authority_keypair: Option<&'c Keypair>,
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
                SwigInstructionBuilder::new(swig_id, client_role, fee_payer.pubkey(), 0);

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

            // Fetch the just-created account data to get the initial role
            #[cfg(not(all(feature = "rust_sdk_test", test)))]
            let swig_data = rpc_client.get_account_data(&swig_account)?;
            #[cfg(all(feature = "rust_sdk_test", test))]
            let swig_data = litesvm.get_account(&swig_account).unwrap().data;

            let swig_with_roles =
                SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;
            let role = swig_with_roles
                .get_role(0)
                .map_err(|_| SwigError::AuthorityNotFound)?;
            let current_role = if let Some(role) = role {
                build_current_role(0, &role)
            } else {
                return Err(SwigError::AuthorityNotFound);
            };

            Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer,
                #[cfg(all(feature = "rust_sdk_test", test))]
                litesvm,
                authority_keypair,
                current_role,
            })
        } else {
            // Safe unwrap because we know the account exists
            #[cfg(not(all(feature = "rust_sdk_test", test)))]
            let swig_data = swig_data.unwrap();
            #[cfg(all(feature = "rust_sdk_test", test))]
            let swig_data = swig_data.unwrap().data;

            let swig_with_roles =
                SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

            let authority_bytes = client_role.authority_bytes()?;
            let role_id = swig_with_roles
                .lookup_role_id(authority_bytes.as_ref())
                .map_err(|_| SwigError::AuthorityNotFound)?
                .ok_or(SwigError::AuthorityNotFound)?;

            // Get the role to verify it exists and has the correct type
            let role = swig_with_roles
                .get_role(role_id)
                .map_err(|_| SwigError::AuthorityNotFound)?;

            // Extract the role data for storage and update odometer if needed
            let current_role = if let Some(role) = &role {
                // Update odometer if this is a Secp256k1 authority
                if let Some(odometer) = role.authority.signature_odometer() {
                    client_role.update_odometer(odometer)?;
                }
                build_current_role(role_id, role)
            } else {
                return Err(SwigError::AuthorityNotFound);
            };

            let instruction_builder =
                SwigInstructionBuilder::new(swig_id, client_role, fee_payer.pubkey(), role_id);

            Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer: &fee_payer,
                #[cfg(all(feature = "rust_sdk_test", test))]
                litesvm,
                authority_keypair,
                current_role,
            })
        }
    }

    /// Adds a new authority to the wallet with specified permissions
    ///
    /// # Arguments
    ///
    /// * `new_authority_type` - The type of authority to add (Ed25519,
    ///   Secp256k1, etc.)
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
            Some(self.get_current_slot()?),
        )?;
        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &instruction,
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
            let instructions = self
                .instruction_builder
                .remove_authority(authority_id, Some(self.get_current_slot()?))?;

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

            let tx_result = self.send_and_confirm_transaction(tx);
            if tx_result.is_ok() {
                self.refresh_permissions()?;
                self.instruction_builder.increment_odometer()?;
            }
            tx_result
        } else {
            return Err(SwigError::AuthorityNotFound);
        }
    }

    /// Signs a transaction containing the provided instructions
    ///
    /// # Arguments
    ///
    /// * `inner_instructions` - Vector of instructions to include in the
    ///   transaction
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

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
    }

    /// Signs instructions using the SignV2 instruction (which uses
    /// swig_wallet_address as authority)
    ///
    /// # Arguments
    ///
    /// * `inner_instructions` - Vector of instructions to sign
    /// * `alt` - Optional slice of Address Lookup Table accounts
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn sign_v2(
        &mut self,
        inner_instructions: Vec<Instruction>,
        alt: Option<&[AddressLookupTableAccount]>,
    ) -> Result<Signature, SwigError> {
        let sign_ix = self
            .instruction_builder
            .sign_v2_instruction(inner_instructions, Some(self.get_current_slot()?))?;

        let alt = if alt.is_some() { alt.unwrap() } else { &[] };

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &sign_ix,
            alt,
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
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
    pub fn update_authority(
        &mut self,
        authority_to_update_id: u32,
        update_data: UpdateAuthorityData,
    ) -> Result<Signature, SwigError> {
        let current_slot = self.get_current_slot()?;
        let counter = self.get_odometer()?;

        let instructions = self.instruction_builder.update_authority(
            authority_to_update_id,
            Some(current_slot),
            update_data,
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &instructions,
            &[],
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
    }

    /// Creates a new sub-account for the Swig wallet
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to create the sub-account for
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn create_sub_account(&mut self) -> Result<Signature, SwigError> {
        let instructions = self
            .instruction_builder
            .create_sub_account(Some(self.get_current_slot()?))?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &instructions,
            &[],
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
    }

    /// Signs instructions with a sub-account
    ///
    /// # Arguments
    ///
    /// * `instructions` - Vector of instructions to sign with the sub-account
    /// * `sub_account` - The public key of the sub-account
    /// * `alt` - Optional slice of Address Lookup Table accounts
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn sign_with_sub_account(
        &mut self,
        instructions: Vec<Instruction>,
        alt: Option<&[AddressLookupTableAccount]>,
    ) -> Result<Signature, SwigError> {
        let current_slot = self.get_current_slot()?;
        let sign_instructions = self
            .instruction_builder
            .sign_instruction_with_sub_account(instructions, Some(current_slot))?;

        let alt = if alt.is_some() { alt.unwrap() } else { &[] };

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &sign_instructions,
            alt,
            self.get_current_blockhash()?,
        )?;

        // We need both the fee payer and the authority to sign
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
    }

    /// Withdraws native SOL from a sub-account
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `amount` - The amount of SOL to withdraw in lamports
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn withdraw_from_sub_account(
        &mut self,
        sub_account: Pubkey,
        amount: u64,
    ) -> Result<Signature, SwigError> {
        let current_slot = self.get_current_slot()?;
        let withdraw_instructions = self.instruction_builder.withdraw_from_sub_account(
            sub_account,
            amount,
            Some(current_slot),
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &withdraw_instructions,
            &[],
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
    }

    /// Withdraws tokens from a sub-account
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `sub_account_token` - The public key of the sub-account's token
    ///   account
    /// * `swig_token` - The public key of the Swig wallet's token account
    /// * `token_program` - The token program ID
    /// * `amount` - The amount of tokens to withdraw
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn withdraw_token_from_sub_account(
        &mut self,
        sub_account: Pubkey,
        sub_account_token: Pubkey,
        swig_token: Pubkey,
        token_program: Pubkey,
        amount: u64,
    ) -> Result<Signature, SwigError> {
        let current_slot = self.get_current_slot()?;
        let withdraw_instructions = self.instruction_builder.withdraw_token_from_sub_account(
            sub_account,
            sub_account_token,
            swig_token,
            token_program,
            amount,
            Some(current_slot),
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &withdraw_instructions,
            &[],
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
    }

    /// Toggles a sub-account's enabled state
    ///
    /// # Arguments
    ///
    /// * `sub_account` - The public key of the sub-account
    /// * `enabled` - Whether to enable or disable the sub-account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the transaction signature or a `SwigError`
    pub fn toggle_sub_account(
        &mut self,
        sub_account: Pubkey,
        auth_role_id: u32,
        sub_account_role_id: u32,
        enabled: bool,
    ) -> Result<Signature, SwigError> {
        let current_slot = self.get_current_slot()?;
        let toggle_instructions = self.instruction_builder.toggle_sub_account(
            sub_account,
            sub_account_role_id,
            auth_role_id,
            enabled,
            Some(current_slot),
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &toggle_instructions,
            &[],
            self.get_current_blockhash()?,
        )?;

        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &self.get_keypairs()?)?;

        let tx_result = self.send_and_confirm_transaction(tx);
        if tx_result.is_ok() {
            self.refresh_permissions()?;
            self.instruction_builder.increment_odometer()?;
        }
        tx_result
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
            .map_err(|e| SwigError::TransactionFailedWithLogs {
                error: e.err.to_string(),
                logs: e.meta.logs,
            })?
            .signature;

        Ok(signature)
    }

    /// Returns the public key of the Swig wallet address
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the Swig wallet address's public key or a
    /// `SwigError`
    pub fn get_swig_wallet_address(&self) -> Result<Pubkey, SwigError> {
        Ok(self.instruction_builder.swig_wallet_address())
    }

    /// Returns the public key of the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the Swig account's public key or a
    /// `SwigError`
    pub fn get_swig_account(&self) -> Result<Pubkey, SwigError> {
        self.instruction_builder.get_swig_account()
    }

    /// Retrieves the current authority's permissions from the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of the authority's permissions or
    /// a `SwigError`
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
    /// This includes account details, roles, and permissions for all
    /// authorities.
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

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let token_accounts = self.rpc_client.get_token_accounts_by_owner(
            &swig_pubkey,
            TokenAccountsFilter::ProgramId(TOKEN_PROGRAM_ID),
        )?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let token_accounts: Vec<solana_client::rpc_response::RpcKeyedAccount> = Vec::new(); // TODO: add token accounts

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let token_accounts_22 = self.rpc_client.get_token_accounts_by_owner(
            &swig_pubkey,
            TokenAccountsFilter::ProgramId(TOKEN_22_PROGRAM_ID),
        )?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let token_accounts_22: Vec<solana_client::rpc_response::RpcKeyedAccount> = Vec::new(); // TODO: add token accounts

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
        if !token_accounts.is_empty() || !token_accounts_22.is_empty() {
            println!("║ Token Balances:");
            for token_account in token_accounts.iter() {
                if let UiAccountData::Json(parsed) = &token_account.account.data {
                    if let Some(token_info) = parsed.parsed.get("info") {
                        println!("║ ├─ Token: {}", token_account.pubkey);
                        println!(
                            "║ │  ├─ Mint: {}",
                            token_info["mint"].as_str().unwrap_or("Unknown")
                        );
                        println!(
                            "║ │  └─ Balance: {}",
                            token_info["tokenAmount"]["uiAmount"]
                                .as_f64()
                                .unwrap_or(0.0)
                        );
                    }
                }
            }
            for token_account in token_accounts_22.iter() {
                if let UiAccountData::Json(parsed) = &token_account.account.data {
                    if let Some(token_info) = parsed.parsed.get("info") {
                        println!("║ ├─ Token v2: {}", token_account.pubkey);
                        println!(
                            "║ │  ├─ Mint: {}",
                            token_info["mint"].as_str().unwrap_or("Unknown")
                        );
                        println!(
                            "║ │  └─ Balance: {}",
                            token_info["tokenAmount"]["uiAmount"]
                                .as_f64()
                                .unwrap_or(0.0)
                        );
                    }
                }
            }
        }

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
                            let mut authority_hex = vec![0x4];
                            authority_hex.extend_from_slice(authority);
                            let authority_hex = hex::encode(authority_hex);
                            let mut hasher = solana_sdk::keccak::Hasher::default();
                            hasher.hash(authority_hex.as_bytes());
                            let hash = hasher.result();
                            let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                            address
                        },
                        AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
                            let authority = role.authority.identity().unwrap();
                            // For Secp256r1, display the compressed public key directly
                            format!("0x{}", hex::encode(authority))
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

                // Check Token Limits
                let token_limits = Role::get_all_actions_of_type::<TokenLimit>(&role)
                    .map_err(|_| SwigError::AuthorityNotFound)?;
                for (index, action) in token_limits.iter().enumerate() {
                    if index == 0 {
                        println!("║ │  ├─ Token Limits");
                    }
                    println!(
                        "║ │  │  ├─ Token {}: {}",
                        index + 1,
                        Pubkey::from(action.token_mint)
                    );
                    println!("║ │  │  ├─ Amount: {} tokens", action.current_amount);
                }

                // Check Token Recurring Limits
                let token_recurring_limits =
                    Role::get_all_actions_of_type::<TokenRecurringLimit>(&role)
                        .map_err(|_| SwigError::AuthorityNotFound)?;
                for (index, action) in token_recurring_limits.iter().enumerate() {
                    if index == 0 {
                        println!("║ │  ├─ Token Recurring Limits");
                    }
                    println!(
                        "║ │  │  ├─ Token {}: {}",
                        index + 1,
                        Pubkey::from(action.token_mint)
                    );
                    println!("║ │  │  ├─ Amount: {} tokens", action.limit);
                    println!("║ │  │  ├─ Window: {} slots", action.window);
                    println!("║ │  │  ├─ Last Reset: Slot {}", action.last_reset);
                    println!("║ │  │  └─ Current Usage: {} tokens", action.current);
                }

                // Check Sol Destination Limits
                let sol_destination_limits =
                    Role::get_all_actions_of_type::<SolDestinationLimit>(&role)
                        .map_err(|_| SwigError::AuthorityNotFound)?;
                for (index, action) in sol_destination_limits.iter().enumerate() {
                    if index == 0 {
                        println!("║ │  ├─ SOL Destination Limits");
                    }
                    println!(
                        "║ │  │  ├─ Destination {}: {}",
                        index + 1,
                        Pubkey::from(action.destination)
                    );
                    println!(
                        "║ │  │  ├─ Amount: {} SOL",
                        action.amount as f64 / 1_000_000_000.0
                    );
                }

                // Check Sol Recurring Destination Limits
                let sol_recurring_destination_limits =
                    Role::get_all_actions_of_type::<SolRecurringDestinationLimit>(&role)
                        .map_err(|_| SwigError::AuthorityNotFound)?;
                for (index, action) in sol_recurring_destination_limits.iter().enumerate() {
                    if index == 0 {
                        println!("║ │  ├─ SOL Recurring Destination Limits");
                    }
                    println!(
                        "║ │  │  ├─ Destination {}: {}",
                        index + 1,
                        Pubkey::from(action.destination)
                    );
                    println!(
                        "║ │  │  ├─ Amount: {} SOL",
                        action.recurring_amount as f64 / 1_000_000_000.0
                    );
                    println!("║ │  │  ├─ Window: {} slots", action.window);
                    println!("║ │  │  ├─ Last Reset: Slot {}", action.last_reset);
                    println!(
                        "║ │  │  └─ Current Usage: {} SOL",
                        action.current_amount as f64 / 1_000_000_000.0
                    );
                }

                // Check Token Destination Limits
                let token_destination_limits =
                    Role::get_all_actions_of_type::<TokenDestinationLimit>(&role)
                        .map_err(|_| SwigError::AuthorityNotFound)?;
                for (index, action) in token_destination_limits.iter().enumerate() {
                    if index == 0 {
                        println!("║ │  ├─ Token Destination Limits");
                    }
                    println!(
                        "║ │  │  ├─ Destination {}: {}",
                        index + 1,
                        Pubkey::from(action.destination)
                    );
                    println!("║ │  │  ├─ Amount: {} tokens", action.amount);
                }

                // Check Token Recurring Destination Limits
                let token_recurring_destination_limits =
                    Role::get_all_actions_of_type::<TokenRecurringDestinationLimit>(&role)
                        .map_err(|_| SwigError::AuthorityNotFound)?;
                for (index, action) in token_recurring_destination_limits.iter().enumerate() {
                    if index == 0 {
                        println!("║ │  ├─ Token Recurring Destination Limits");
                    }
                    println!(
                        "║ │  │  ├─ Destination {}: {}",
                        index + 1,
                        Pubkey::from(action.destination)
                    );
                    println!("║ │  │  ├─ Amount: {} tokens", action.recurring_amount);
                    println!("║ │  │  ├─ Window: {} slots", action.window);
                    println!("║ │  │  ├─ Last Reset: Slot {}", action.last_reset);
                    println!("║ │  │  └─ Current Usage: {} tokens", action.current_amount);
                }

                // Check Program Scopes
                let program_scopes = Role::get_all_actions_of_type::<ProgramScope>(&role)
                    .map_err(|_| SwigError::AuthorityNotFound)?;
                for (index, action) in program_scopes.iter().enumerate() {
                    let program_id = Pubkey::from(action.program_id);
                    let target_account = Pubkey::from(action.target_account);
                    if index == 0 {
                        println!("║ │  ├─ Program Scopes");
                    }
                    println!("║ │  │  ├─ Scope {}: Program ID: {}", index + 1, program_id);
                    println!("║ │  │  ├─ Target Account: {}", target_account);
                    println!(
                        "║ │  │  ├─ Scope Type: {}",
                        match action.scope_type {
                            0 => "Basic",
                            1 => "Limit",
                            2 => "Recurring Limit",
                            _ => "Unknown",
                        }
                    );
                    println!(
                        "║ │  │  ├─ Numeric Type: {}",
                        match action.numeric_type {
                            0 => "U64",
                            1 => "U128",
                            2 => "F64",
                            _ => "Unknown",
                        }
                    );
                    if action.scope_type > 0 {
                        println!("║ │  │  ├─ Limit: {} ", action.limit);
                        println!("║ │  │  ├─ Current Usage: {} ", action.current_amount);
                    }
                    if action.scope_type == 2 {
                        println!("║ │  │  ├─ Window: {} slots", action.window);
                        println!("║ │  │  ├─ Last Reset: Slot {}", action.last_reset);
                    }
                    println!("║ │  │  ");
                }

                // Check Sub Accounts
                let actions = Role::get_all_actions_of_type::<SubAccount>(&role)
                    .map_err(|_| SwigError::AuthorityNotFound)?;
                if !actions.is_empty() {
                    {
                        println!("║ │  ├─ SubAccount");
                        for action in actions {
                            println!(
                                "║ │  │  ├─ SubAccount: {}",
                                Pubkey::from(action.sub_account)
                            );
                            println!("║ │  │  ├─ Enabled: {}", action.enabled);
                            println!("║ │  │  ├─ Role ID: {}", action.role_id);
                            println!("║ │  │  └─ Swig ID: {}", Pubkey::from(action.swig_id));
                        }
                    }
                }

                println!("║ │  ");
            }
        }

        println!("╚══════════════════════════════════════════════════════════════════");

        Ok(())
    }

    /// Get role id
    ///
    /// # Arguments
    ///
    /// * `authority` - The authority's public key as bytes to lookup
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the role id or a `SwigError` if the
    /// authority is not found
    pub fn get_role_id(&self, authority: &[u8]) -> Result<u32, SwigError> {
        let swig_pubkey = self.get_swig_account()?;

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;
        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        let role_id = swig_with_roles.lookup_role_id(authority.as_ref()).unwrap();
        if role_id.is_some() {
            Ok(role_id.unwrap())
        } else {
            Err(SwigError::AuthorityNotFound)
        }
    }

    /// Returns the role id of the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the role id of the Swig account or a
    /// `SwigError`
    pub fn get_current_role_id(&self) -> Result<u32, SwigError> {
        Ok(self.instruction_builder.get_role_id())
    }

    /// Returns the current role permissions if available
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the current role permissions or a
    /// `SwigError`
    pub fn get_current_permissions(&self) -> Result<&[Permission], SwigError> {
        Ok(&self.current_role.permissions)
    }

    /// Updates the stored role permissions by fetching them from the chain
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn refresh_permissions(&mut self) -> Result<(), SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;

        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        let role_id = self.get_current_role_id()?;
        let role = swig_with_roles
            .get_role(role_id)
            .map_err(|_| SwigError::AuthorityNotFound)?;

        if let Some(role) = role {
            self.current_role = build_current_role(role_id, &role);
        } else {
            return Err(SwigError::AuthorityNotFound);
        }

        Ok(())
    }

    /// Switches to a different authority for the Swig wallet
    ///
    /// # Arguments
    ///
    /// * `role_id` - The new role ID to switch to
    /// * `client_role` - The client role implementation specifying the type of
    ///   signing authority
    /// * `authority_kp` - The public key of the new authority (unused in new
    ///   implementation)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing unit type or a `SwigError`
    pub fn switch_authority(
        &mut self,
        role_id: u32,
        mut client_role: Box<dyn ClientRole>,
        authority_kp: Option<&'c Keypair>,
    ) -> Result<(), SwigError> {
        // The odometer is stored in client role and must be updated to match the on
        // chain odometer
        let odometer = self.with_role_data(role_id, |role| role.authority.signature_odometer())?;
        if let Some(onchain_odometer) = odometer {
            client_role.update_odometer(onchain_odometer)?;
        }

        // Update the instruction builder's authority
        self.instruction_builder
            .switch_authority(role_id, client_role)?;

        self.authority_keypair = authority_kp;

        // Update the stored role data for the new authority
        self.refresh_permissions()?;

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
    /// Returns a `Result` containing unit type or a `SwigError` if the
    /// authority is not found
    pub fn authenticate_authority(&self, authority: &[u8]) -> Result<(), SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;
        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        let indexed_authority = swig_with_roles.lookup_role_id(authority.as_ref()).unwrap();

        if indexed_authority.is_some() {
            Ok(())
        } else {
            Err(SwigError::AuthorityNotFound)
        }
    }

    /// Creates a new session for the Swig wallet
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
        let create_session_instructions = self.instruction_builder.create_session_instruction(
            session_key,
            duration,
            Some(current_slot),
            None,
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &create_session_instructions,
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

    /// Get the sub account if it exists
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the sub account or a `SwigError`
    pub fn get_sub_account(&self) -> Result<Option<Pubkey>, SwigError> {
        let (sub_account, sub_account_bump) = Pubkey::find_program_address(
            &sub_account_seeds(
                self.instruction_builder.get_swig_id(),
                &self.get_current_role_id()?.to_le_bytes(),
            ),
            &swig_interface::program_id(),
        );

        // Check if the sub account exists
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let account_exists = self.rpc_client.get_account(&sub_account).is_ok();
        #[cfg(all(feature = "rust_sdk_test", test))]
        let account_exists = self.litesvm.get_balance(&sub_account).is_some();

        if account_exists {
            Ok(Some(sub_account))
        } else {
            Ok(None)
        }
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

    /// Returns the keypairs for signing transactions
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the keypairs for signing transactions or a
    /// `SwigError`
    fn get_keypairs(&self) -> Result<Vec<&Keypair>, SwigError> {
        let mut keypairs = vec![self.fee_payer];
        if let Some(authority_kp) = self.authority_keypair {
            // Only add the authority keypair if it's different from the fee payer
            if authority_kp.pubkey() == self.fee_payer.pubkey() {
                // Authority and fee payer are the same, so we already have it
            } else {
                keypairs.push(authority_kp);
            }
        }
        Ok(keypairs)
    }

    /// Returns the swig id
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the swig id or a `SwigError`
    pub fn get_swig_id(&self) -> &[u8; 32] {
        &self.instruction_builder.get_swig_id()
    }

    /// Creates an associated token account for the Swig wallet
    ///
    /// # Arguments
    ///
    /// * `mint` - The mint address of the token to create an ATA for
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the associated token address or a
    /// `SwigError`
    pub fn create_ata(&mut self, mint: &Pubkey) -> Result<Pubkey, SwigError> {
        let swig_wallet_address = self.instruction_builder.get_swig_account()?;
        let associated_token_address = get_associated_token_address(&swig_wallet_address, &mint);

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        {
            // Check if the ATA already exists
            let account_exists = self
                .rpc_client
                .get_account(&associated_token_address)
                .is_ok();

            if !account_exists {
                // Create the instruction to create the ATA
                let create_ata_instruction = create_associated_token_account(
                    &self.fee_payer.pubkey(), // payer
                    &swig_wallet_address,     // owner
                    &mint,                    // mint
                    &TOKEN_PROGRAM_ID,
                );

                // Get recent blockhash
                let recent_blockhash = self.rpc_client.get_latest_blockhash()?;

                // Create and sign the transaction
                let transaction = Transaction::new_signed_with_payer(
                    &[create_ata_instruction],
                    Some(&self.fee_payer.pubkey()),
                    &[&self.fee_payer.insecure_clone()],
                    recent_blockhash,
                );

                // Send the transaction
                let signature = self.rpc_client.send_and_confirm_transaction(&transaction)?;

                println!(
                    "Success! Associated Token Account created. Transaction Signature: {}",
                    signature
                );
            } else {
                println!("Associated Token Account already exists.");
            }
        }

        #[cfg(all(feature = "rust_sdk_test", test))]
        CreateAssociatedTokenAccount::new(&mut self.litesvm, self.fee_payer, &mint)
            .owner(&swig_wallet_address)
            .send()
            .map_err(|_| anyhow::anyhow!("Failed to create associated token account"))?;

        Ok(associated_token_address)
    }

    /// Creates an associated token account for the Swig wallet
    ///
    /// # Arguments
    ///
    /// * `mint` - The mint address of the token to create an ATA for
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the associated token address or a
    /// `SwigError`
    pub fn create_wallet_ata(&mut self, mint: &Pubkey) -> Result<Pubkey, SwigError> {
        let swig_wallet_address = self.instruction_builder.swig_wallet_address();
        let associated_token_address = get_associated_token_address(&swig_wallet_address, &mint);

        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        {
            // Check if the ATA already exists
            let account_exists = self
                .rpc_client
                .get_account(&associated_token_address)
                .is_ok();

            if !account_exists {
                // Create the instruction to create the ATA
                let create_ata_instruction = create_associated_token_account(
                    &self.fee_payer.pubkey(), // payer
                    &swig_wallet_address,     // owner
                    &mint,                    // mint
                    &TOKEN_PROGRAM_ID,
                );

                // Get recent blockhash
                let recent_blockhash = self.rpc_client.get_latest_blockhash()?;

                // Create and sign the transaction
                let transaction = Transaction::new_signed_with_payer(
                    &[create_ata_instruction],
                    Some(&self.fee_payer.pubkey()),
                    &[&self.fee_payer.insecure_clone()],
                    recent_blockhash,
                );

                // Send the transaction
                let signature = self.rpc_client.send_and_confirm_transaction(&transaction)?;

                println!(
                    "Success! Associated Token Account created. Transaction Signature: {}",
                    signature
                );
            } else {
                println!("Associated Token Account already exists.");
            }
        }

        #[cfg(all(feature = "rust_sdk_test", test))]
        CreateAssociatedTokenAccount::new(&mut self.litesvm, self.fee_payer, &mint)
            .owner(&swig_wallet_address)
            .send()
            .map_err(|_| anyhow::anyhow!("Failed to create associated token account"))?;

        Ok(associated_token_address)
    }

    /// Returns the fee payer's public key
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the fee payer's public key
    pub fn get_fee_payer(&self) -> Pubkey {
        self.fee_payer.pubkey()
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

    /// Checks if the current authority has a specific permission
    ///
    /// # Arguments
    ///
    /// * `permission` - The permission to check for
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing whether the permission exists or a
    /// `SwigError`
    pub fn has_permission(&self, permission: &Permission) -> Result<bool, SwigError> {
        let permissions = self.get_current_permissions()?;
        Ok(permissions.contains(permission))
    }

    /// Checks if the current authority has "All" permissions
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing whether the authority has all permissions
    /// or a `SwigError`
    pub fn has_all_permissions(&self) -> Result<bool, SwigError> {
        let permissions = self.get_current_permissions()?;
        Ok(permissions.iter().any(|p| matches!(p, Permission::All)))
    }

    /// Checks if the current authority has manage authority permissions
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing whether the authority can manage other
    /// authorities or a `SwigError`
    pub fn can_manage_authority(&self) -> Result<bool, SwigError> {
        let permissions = self.get_current_permissions()?;
        Ok(permissions
            .iter()
            .any(|p| matches!(p, Permission::ManageAuthority)))
    }

    /// Gets the SOL spending limit for the current authority
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the SOL limit in lamports or a `SwigError`
    pub fn get_sol_limit(&self) -> Result<Option<u64>, SwigError> {
        let permissions = self.get_current_permissions()?;
        for permission in permissions {
            if let Permission::Sol { amount, .. } = permission {
                return Ok(Some(*amount));
            }
        }
        Ok(None)
    }

    /// Gets the recurring SOL limit configuration for the current authority
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the recurring SOL limit config or a
    /// `SwigError`
    pub fn get_recurring_sol_limit(&self) -> Result<Option<RecurringConfig>, SwigError> {
        let permissions = self.get_current_permissions()?;
        for permission in permissions {
            if let Permission::Sol { recurring, .. } = permission {
                return Ok(recurring.clone());
            }
        }
        Ok(None)
    }

    /// Checks if the current authority can spend a specific amount of SOL
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount to check in lamports
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing whether the authority can spend the amount
    /// or a `SwigError`
    pub fn can_spend_sol(&self, amount: u64) -> Result<bool, SwigError> {
        // If they have all permissions, they can spend any amount
        if self.has_all_permissions()? {
            return Ok(true);
        }

        let permissions = self.get_current_permissions()?;

        for permission in permissions {
            match permission {
                Permission::Sol {
                    amount: limit,
                    recurring,
                } => {
                    // Check one-time limit
                    if amount <= *limit {
                        return Ok(true);
                    }

                    // Check recurring limit if it exists
                    if let Some(recurring_config) = recurring {
                        if amount <= recurring_config.current_amount {
                            return Ok(true);
                        }
                    }
                },
                _ => continue,
            }
        }

        Ok(false)
    }

    /// Gets the total number of roles in the Swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the number of roles or a `SwigError`
    pub fn get_role_count(&self) -> Result<u32, SwigError> {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;

        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        Ok(swig_with_roles.state.role_counter)
    }

    /// Gets the authority type for a specific role
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to check
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the authority type or a `SwigError`
    pub fn get_authority_type(&self, role_id: u32) -> Result<AuthorityType, SwigError> {
        self.with_role_data(role_id, |role| role.authority.authority_type())
    }

    /// Gets the public key for the swig account
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the public key for the swig account or a
    /// `SwigError`
    pub fn get_swig(&self) -> Pubkey {
        self.instruction_builder.get_swig_account().unwrap()
    }

    /// Gets the authority identity for a specific role
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to check
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the authority identity bytes or a
    /// `SwigError`
    pub fn get_authority_identity(&self, role_id: u32) -> Result<Vec<u8>, SwigError> {
        self.with_role_data(role_id, |role| {
            role.authority.identity().unwrap_or_default().to_vec()
        })
    }

    /// Checks if a role is session-based
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to check
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing whether the role is session-based or a
    /// `SwigError`
    pub fn is_session_based(&self, role_id: u32) -> Result<bool, SwigError> {
        self.with_role_data(role_id, |role| role.authority.session_based())
    }

    /// Gets all permissions for a specific role
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to get permissions for
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the permissions for the role or a
    /// `SwigError`
    pub fn get_role_permissions(&self, role_id: u32) -> Result<Vec<Permission>, SwigError> {
        self.with_role_data(role_id, |role| Permission::from_role(role))?
    }

    /// Checks if a role has a specific permission
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to check
    /// * `permission` - The permission to check for
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing whether the role has the permission or a
    /// `SwigError`
    pub fn role_has_permission(
        &self,
        role_id: u32,
        permission: &Permission,
    ) -> Result<bool, SwigError> {
        let permissions = self.get_role_permissions(role_id)?;
        Ok(permissions.contains(permission))
    }

    /// Gets the formatted authority address for display
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to get the address for
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the formatted address string or a
    /// `SwigError`
    pub fn get_formatted_authority_address(&self, role_id: u32) -> Result<String, SwigError> {
        self.with_role_data(role_id, |role| match role.authority.authority_type() {
            AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                let authority = role.authority.identity().unwrap_or_default();
                Ok(bs58::encode(authority).into_string())
            },
            AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                let authority = role.authority.identity().unwrap();
                let mut authority_hex = vec![0x4];
                authority_hex.extend_from_slice(authority);
                let authority_hex = hex::encode(authority_hex);
                let mut hasher = solana_sdk::keccak::Hasher::default();
                hasher.hash(authority_hex.as_bytes());
                let hash = hasher.result();
                let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                Ok(address)
            },
            AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => {
                let authority = role.authority.identity().unwrap();
                // For Secp256r1, display the compressed public key directly
                Ok(format!("0x{}", hex::encode(authority)))
            },
            _ => Err(SwigError::AuthorityNotFound),
        })?
    }

    /// Get the odometer for the current authority if it is a Secp256k1
    /// authority
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the odometer or a `SwigError`
    pub fn get_odometer(&self) -> Result<u32, SwigError> {
        self.instruction_builder.get_odometer()
    }

    /// Helper method to work with role data by ID using a closure
    ///
    /// # Arguments
    ///
    /// * `role_id` - The ID of the role to retrieve
    /// * `f` - Closure to execute with the role data
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the result of the closure or a `SwigError`
    fn with_role_data<F, T>(&self, role_id: u32, f: F) -> Result<T, SwigError>
    where
        F: FnOnce(&Role) -> T,
    {
        let swig_pubkey = self.get_swig_account()?;
        #[cfg(not(all(feature = "rust_sdk_test", test)))]
        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        #[cfg(all(feature = "rust_sdk_test", test))]
        let swig_data = self.litesvm.get_account(&swig_pubkey).unwrap().data;

        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|_| SwigError::InvalidSwigData)?;

        if let Some(role) = swig_with_roles
            .get_role(role_id)
            .map_err(|_| SwigError::InvalidSwigData)?
        {
            Ok(f(&role))
        } else {
            Err(SwigError::AuthorityNotFound)
        }
    }
}

// Helper to build CurrentRole from a Role and role_id
fn build_current_role(role_id: u32, role: &Role) -> crate::types::CurrentRole {
    crate::types::CurrentRole {
        role_id,
        authority_type: role.authority.authority_type(),
        authority_identity: role.authority.identity().unwrap_or_default().to_vec(),
        permissions: crate::types::Permission::from_role(role).unwrap_or_default(),
        session_based: role.authority.session_based(),
    }
}

#[cfg(all(feature = "rust_sdk_test", test))]
mod tests {
    use super::*;
    use crate::tests::wallet::*;
}
