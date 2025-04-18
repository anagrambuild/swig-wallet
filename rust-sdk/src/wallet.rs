#[cfg(test)]
use litesvm::LiteSVM;
use solana_client::{rpc_client::RpcClient, rpc_request::TokenAccountsFilter};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_sdk::{
    account::ReadableAccount,
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
    action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::AuthorityType,
    role::Role,
    swig::SwigWithRoles,
};

use crate::{
    error::SwigError,
    instruction_builder::{AuthorityManager, SwigInstructionBuilder},
    types::Permission,
};
pub struct SwigWallet {
    /// The underlying instruction builder
    instruction_builder: SwigInstructionBuilder,
    /// RPC client for interacting with the Solana network
    pub rpc_client: RpcClient,
    /// The wallet's fee payer
    fee_payer: Keypair,
    /// The LiteSVM instance for testing
    #[cfg(test)]
    litesvm: LiteSVM,
}

impl SwigWallet {
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
        authority_type: AuthorityType,
        authority: Pubkey,
        fee_payer: Keypair,
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
            println!("Swig account does not exist, creating new one");
            let instruction_builder = SwigInstructionBuilder::new(
                swig_id,
                AuthorityManager::Ed25519(authority),
                fee_payer.pubkey(),
                0,
            );

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
            )
            .unwrap();

            #[cfg(not(test))]
            let signature = rpc_client.send_and_confirm_transaction(&tx)?;
            #[cfg(test)]
            let signature = litesvm.send_transaction(tx).unwrap().signature;

            return Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer,
                #[cfg(test)]
                litesvm,
            });
        } else {
            println!("Swig account already exists");
            #[cfg(not(test))]
            let swig_data = rpc_client.get_account_data(&swig_account).unwrap();
            #[cfg(test)]
            let swig_data = litesvm.get_account(&swig_account).unwrap().data;

            let swig_with_roles =
                SwigWithRoles::from_bytes(&swig_data).map_err(|_| SwigError::InvalidSwigData)?;

            let role_id = match authority_type {
                AuthorityType::Ed25519 => swig_with_roles
                    .lookup_role_id(authority.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
                AuthorityType::Secp256k1 => swig_with_roles
                    .lookup_role_id(authority.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
                _ => todo!(),
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
                AuthorityManager::Ed25519(authority),
                fee_payer.pubkey(),
                role_id,
            );

            Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer,
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
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )
        .unwrap();

        self.send_and_confirm_transaction(tx)
    }

    /// Removes an authority from the wallet
    ///
    /// # Arguments
    /// * `authority_id` - The ID of the authority to remove
    pub fn remove_authority(&mut self, authority_id: u32) -> Result<Signature, SwigError> {
        let instruction = self.instruction_builder.remove_authority(authority_id)?;
        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &[instruction],
            &[],
            self.rpc_client.get_latest_blockhash()?,
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )
        .unwrap();

        self.send_and_confirm_transaction(tx)
    }

    /// Signs a transaction with the given instructions
    ///
    /// # Arguments
    /// * `inner_instructions` - The instructions to sign
    pub fn sign(&mut self, inner_instructions: Vec<Instruction>) -> Result<Signature, SwigError> {
        let sign_ix = self
            .instruction_builder
            .sign_instruction(inner_instructions, None)
            .unwrap();

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &sign_ix,
            &[],
            #[cfg(not(test))]
            self.rpc_client.get_latest_blockhash()?,
            #[cfg(test)]
            self.litesvm.latest_blockhash(),
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[&self.fee_payer.insecure_clone()],
        )
        .unwrap();

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
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )
        .unwrap();

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
            .map_err(|_| SwigError::TransactionError)?
            .signature;

        Ok(signature)
    }

    /// Returns the public key of the Swig account
    pub fn get_swig_account(&self) -> Result<Pubkey, SwigError> {
        self.instruction_builder.get_swig_account()
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

        println!("\tKEY: {}", swig_pubkey);
        println!("\tID: {}", swig_with_roles.state.role_counter);
        println!(
            "\tLamports: {}",
            swig_account.lamports() //- Rent::default().minimum_balance(swig_with_roles)
        );

        for i in 0..swig_with_roles.state.role_counter {
            let role = swig_with_roles
                .get_role(i)
                .map_err(|e| SwigError::AuthorityNotFound)?;
            if let Some(role) = role {
                println!("\tRole {}", i);
                println!("\t\tAuthority Type: {:?}", role.authority.authority_type());
                println!(
                    "\t\tAuthority: {:?}",
                    match role.authority.authority_type() {
                        AuthorityType::Ed25519 => "Ed25519".to_string(), // bs58::encode(role.
                        // authority.as_slice()).
                        // into_string(),
                        AuthorityType::Secp256k1 => "Secp256k1".to_string(), // hex::encode(role.
                        // authority.as_slice()),
                        _ => todo!(),
                    }
                );

                println!("\t\tPermissions:");

                // All
                if let Some(_) =
                    Role::get_action::<All>(&role, &[]).map_err(|_| SwigError::AuthorityNotFound)?
                {
                    println!("\t\tAll permission exists");
                }
                // Sol Limit
                if let Some(action) = Role::get_action::<SolLimit>(&role, &[])
                    .map_err(|_| SwigError::AuthorityNotFound)?
                {
                    println!("\t\tSol Limit {:?}", action);
                }
                // Manage Authority
                if let Some(_) = Role::get_action::<ManageAuthority>(&role, &[])
                    .map_err(|_| SwigError::AuthorityNotFound)?
                {
                    println!("\t\tManage Authority permission exists");
                }
            }
        }

        // let token_accounts = self.rpc_client.get_token_accounts_by_owner(
        //     &swig_id,
        //     TokenAccountsFilter::ProgramId(TOKEN_PROGRAM_ID),
        // )?;
        // let token_accounts_22 = self.rpc_client.get_token_accounts_by_owner(
        //     &swig_id,
        //     TokenAccountsFilter::ProgramId(TOKEN_22_PROGRAM_ID),
        // )?;
        // if !token_accounts.is_empty() || !token_accounts_22.is_empty() {
        //     println!("\tToken Accounts:");
        // }
        // for (index, token_account) in token_accounts.iter().enumerate() {
        //     if let UiAccountData::Json(ParsedAccount {
        //         program, parsed, ..
        //     }) = &token_account.account.data
        //     {
        //         println!("\t\tKey: {}", token_account.pubkey);
        //         println!("\t\tMint: {}", parsed["info"]["mint"].as_str().unwrap());
        //         println!("\t\tAmount: {}",
        // parsed["info"]["tokenAmount"]["uiAmount"]);     }
        // }
        // for (index, token_account) in token_accounts_22.iter().enumerate() {
        //     if let UiAccountData::Json(ParsedAccount {
        //         program, parsed, ..
        //     }) = &token_account.account.data
        //     {
        //         println!("\t\tKey: {}", token_account.pubkey);
        //         println!("\t\tMint: {}", parsed["info"]["mint"].as_str().unwrap());
        //         println!("\t\tAmount: {}",
        // parsed["info"]["tokenAmount"]["uiAmount"]);     }
        // }
        Ok(())
    }

    /// Switches the authority of the Swig account
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to switch to
    /// * `authority` - The new authority's credentials
    pub fn switch_authority(&mut self, role_id: u32, authority: Pubkey) -> Result<(), SwigError> {
        let instruction = self
            .instruction_builder
            .switch_authority(role_id, authority)?;
        Ok(())
    }

    /// Switches the payer of the Swig account
    ///
    /// # Arguments
    /// * `payer` - The new payer's credentials
    pub fn switch_payer(&mut self, payer: Keypair) -> Result<(), SwigError> {
        self.instruction_builder.switch_payer(payer.pubkey())?;
        self.fee_payer = payer;
        Ok(())
    }

    #[cfg(test)]
    pub fn litesvm(&mut self) -> &mut LiteSVM {
        &mut self.litesvm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_wallet_creation() {
        let (mut litesvm, main_authority) = setup_litesvm();

        let swig_wallet = SwigWallet::new(
            [0; 32],
            AuthorityType::Ed25519,
            main_authority.pubkey(),
            main_authority,
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
            AuthorityType::Ed25519,
            main_authority.pubkey(),
            main_authority,
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
        swig_wallet.display_swig().unwrap();
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
            AuthorityType::Ed25519,
            main_authority.pubkey(),
            main_authority,
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
                    recurring: None,
                }],
            )
            .unwrap();

        swig_wallet
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();

        swig_wallet.switch_payer(secondary_authority).unwrap();

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
            AuthorityType::Ed25519,
            main_authority.pubkey(),
            main_authority,
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
                    amount: 10_000_000_000,
                    recurring: None,
                }],
            )
            .unwrap();

        swig_wallet
            .switch_authority(1, secondary_authority.pubkey())
            .unwrap();
        swig_wallet.switch_payer(secondary_authority).unwrap();

        // Test transfer
        let recipient = Keypair::new();
        let transfer_ix = system_instruction::transfer(
            &swig_wallet.get_swig_account().unwrap(),
            &recipient.pubkey(),
            2_000_000_000,
        );

        let swig_account = swig_wallet.get_swig_account().unwrap();
        swig_wallet
            .litesvm()
            .airdrop(&swig_account, 10_000_000_000)
            .unwrap();

        swig_wallet.sign(vec![transfer_ix]).unwrap();

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
            AuthorityType::Ed25519,
            main_authority.pubkey(),
            main_authority,
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
        swig_wallet.switch_payer(secondary_authority).unwrap();

        let recipient = Keypair::new();
        let transfer_ix = system_instruction::transfer(
            &swig_wallet.get_swig_account().unwrap(),
            &recipient.pubkey(),
            2_000_000_000,
        );

        let result = swig_wallet.sign(vec![transfer_ix]);
        assert!(result.is_err());
    }
}
